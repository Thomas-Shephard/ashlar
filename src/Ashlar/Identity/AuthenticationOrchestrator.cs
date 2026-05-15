using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class AuthenticationOrchestrator(
    IAuthenticationPipeline pipeline,
    IAuthenticationHandshakeService handshakeService,
    IMfaPolicyEvaluator policyEvaluator,
    IOptions<MfaOrchestrationOptions>? globalOptions = null)
    : IAuthenticationOrchestrator
{
    private readonly IAuthenticationPipeline _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
    private readonly IAuthenticationHandshakeService _handshakeService = handshakeService ?? throw new ArgumentNullException(nameof(handshakeService));
    private readonly IMfaPolicyEvaluator _policyEvaluator = policyEvaluator ?? throw new ArgumentNullException(nameof(policyEvaluator));
    private readonly MfaOrchestrationOptions _globalOptions = globalOptions?.Value ?? new MfaOrchestrationOptions();

    public async Task<MfaAuthenticationResult> AuthenticateAsync(
        AuthenticationContext context,
        IAuthenticationAssertion primaryAssertion,
        MfaOrchestrationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(primaryAssertion);

        var response = await _pipeline.LoginAsync(context, primaryAssertion, cancellationToken);
        options ??= _globalOptions;

        if (!response.Succeeded && response.Status != AuthenticationStatus.MfaRequired)
        {
            return response.Status switch
            {
                AuthenticationStatus.Disabled => new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: "User is disabled."),
                _ => new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: "Authentication failed.")
            };
        }

        if (response.User == null)
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Authentication failed.");
        }

        var policyEvaluation = await _policyEvaluator.EvaluateAsync(response.User, context, cancellationToken);

        if (response.Status == AuthenticationStatus.MfaRequired || policyEvaluation.IsMfaRequired)
        {
            return await CreateMfaRequiredResultAsync(response.User, response, policyEvaluation, options, cancellationToken);
        }

        return new MfaAuthenticationResult(
            MfaAuthenticationStatus.Succeeded,
            response.User,
            Claims: response.Claims);
    }

    public async Task<MfaAuthenticationResult> VerifyFactorAsync(
        string handshakeToken,
        string factorType,
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(handshakeToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(factorType);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        var handshake = await _handshakeService.GetHandshakeAsync(handshakeToken, cancellationToken);
        if (handshake == null)
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Handshake not found.");
        }

        if (!TryResolveRequiredFactor(handshake, factorType, out var resolvedFactorType))
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Invalid factor type.");
        }

        if (handshake.VerifiedFactors.Any(verifiedFactor => FactorsMatch(verifiedFactor, resolvedFactorType)))
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Factor already verified.");
        }

        if (!IsAssertionAuthorizedForFactor(assertion, resolvedFactorType))
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Factor verification failed.");
        }

        var factorContext = context with { UserId = handshake.UserId };
        var response = await _pipeline.LoginAsync(factorContext, assertion, cancellationToken);
        if (!response.Succeeded || response.User?.Id != handshake.UserId)
        {
            var errorMessage = response.Status == AuthenticationStatus.Disabled ? "User is disabled." : "Factor verification failed.";
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: errorMessage);
        }

        // Capture any new claims from this factor
        var metadata = new Dictionary<string, string>();
        if (response.Claims != null)
        {
            foreach (var claim in response.Claims)
            {
                metadata[$"claim:{claim.Key}"] = claim.Value;
            }
        }

        var result = await _handshakeService.VerifyFactorAsync(
            new VerifyAuthenticationHandshakeRequest(handshakeToken, resolvedFactorType, metadata),
            cancellationToken);

        if (!result.Succeeded || result.Value == null)
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: result.FailureReason ?? "Factor verification failed.");
        }

        return CreateResultFromHandshake(result.Value, response.User, handshakeToken);
    }

    private static MfaAuthenticationResult CreateResultFromHandshake(AuthenticationHandshake handshake, IUser user, string handshakeToken)
    {
        if (handshake.IsCompleted)
        {
            var claims = ExtractClaims(handshake.Metadata);

            return new MfaAuthenticationResult(
                MfaAuthenticationStatus.Succeeded,
                User: user,
                Claims: claims);
        }

        return new MfaAuthenticationResult(
            MfaAuthenticationStatus.HandshakeIncomplete,
            User: user,
            HandshakeToken: handshakeToken,
            RequiredFactors: handshake.RequiredFactors
                .Where(requiredFactor => !handshake.VerifiedFactors.Any(verifiedFactor => FactorsMatch(requiredFactor, verifiedFactor)))
                .ToArray());
    }

    private async Task<MfaAuthenticationResult> CreateMfaRequiredResultAsync(
        IUser user,
        AuthenticationResponse response,
        MfaPolicyEvaluation policyEvaluation,
        MfaOrchestrationOptions options,
        CancellationToken cancellationToken)
    {
        var requiredFactors = ResolveRequiredFactors(policyEvaluation, response.Claims, options.ProviderFactorsClaimName);
        if (requiredFactors.Count == 0)
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: "MFA is required but no factors are configured.");
        }

        var result = await _handshakeService.CreateHandshakeAsync(
            new CreateAuthenticationHandshakeRequest(user.Id, requiredFactors, BuildClaimMetadata(response.Claims)),
            cancellationToken);

        if (!result.Succeeded)
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: result.FailureReason ?? "Failed to create MFA handshake.");
        }

        return new MfaAuthenticationResult(
            MfaAuthenticationStatus.MfaRequired,
            user,
            result.Value!.Token,
            result.Value!.Handshake.RequiredFactors);
    }

    private static HashSet<string> ResolveRequiredFactors(
        MfaPolicyEvaluation policyEvaluation,
        IDictionary<string, string>? claims,
        string providerFactorsClaimName)
    {
        var requiredFactors = new HashSet<string>(
            NormalizeRequiredFactors(policyEvaluation.Requirement?.RequiredFactors),
            StringComparer.OrdinalIgnoreCase);

        if (requiredFactors.Count == 0 &&
            claims?.TryGetValue(providerFactorsClaimName, out var providerFactors) == true &&
            !string.IsNullOrWhiteSpace(providerFactors))
        {
            requiredFactors.UnionWith(providerFactors
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(factor => !string.IsNullOrWhiteSpace(factor)));
        }

        return requiredFactors;
    }

    private static Dictionary<string, string> BuildClaimMetadata(IDictionary<string, string>? claims)
    {
        return claims?.ToDictionary(claim => $"claim:{claim.Key}", claim => claim.Value) ?? [];
    }

    private static Dictionary<string, string> ExtractClaims(IDictionary<string, string>? metadata)
    {
        return metadata?
            .Where(kvp => kvp.Key.StartsWith("claim:", StringComparison.Ordinal))
            .ToDictionary(kvp => kvp.Key[6..], kvp => kvp.Value) ?? [];
    }

    private static bool IsAssertionAuthorizedForFactor(IAuthenticationAssertion assertion, string factorType)
    {
        var normalizedFactorType = NormalizeFactorType(factorType);
        var providerIdentity = assertion.ProviderIdentity;

        return NormalizeFactorType(providerIdentity.Name) == normalizedFactorType ||
            NormalizeFactorType(providerIdentity.Type == default ? null : providerIdentity.Type.Value) == normalizedFactorType ||
            NormalizeFactorType(providerIdentity.ToString()) == normalizedFactorType;
    }

    private static IEnumerable<string> NormalizeRequiredFactors(IEnumerable<string>? factors)
    {
        return factors?.Where(factor => !string.IsNullOrWhiteSpace(factor)).Select(factor => factor.Trim()) ?? [];
    }

    private static bool TryResolveRequiredFactor(AuthenticationHandshake handshake, string factorType, out string resolvedFactorType)
    {
        var requiredFactor = handshake.RequiredFactors.FirstOrDefault(requiredFactor => FactorsMatch(requiredFactor, factorType));

        resolvedFactorType = requiredFactor ?? string.Empty;
        return requiredFactor != null;
    }

    private static bool FactorsMatch(string left, string right)
    {
        return StringComparer.OrdinalIgnoreCase.Equals(left, right) ||
            NormalizeFactorType(left) == NormalizeFactorType(right);
    }

    private static string NormalizeFactorType(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = string.Concat(value.Where(char.IsLetterOrDigit)).ToUpperInvariant();
        return string.IsNullOrEmpty(normalized) ? value.ToUpperInvariant() : normalized;
    }
}
