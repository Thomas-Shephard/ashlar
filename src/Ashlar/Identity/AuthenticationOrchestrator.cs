using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

/// <summary>
/// Provides authentication orchestrator behavior.
/// </summary>
/// <param name="pipeline">The pipeline value.</param>
/// <param name="handshakeService">The handshake service value.</param>
/// <param name="policyEvaluator">The policy evaluator value.</param>
/// <param name="globalOptions">The global options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class AuthenticationOrchestrator(
    IAuthenticationPipeline pipeline,
    IAuthenticationHandshakeService handshakeService,
    IMfaPolicyEvaluator policyEvaluator,
    IOptions<MfaOrchestrationOptions>? globalOptions = null,
    ILogger<AuthenticationOrchestrator>? logger = null)
    : IAuthenticationOrchestrator
{
    private const string PrimaryProviderTypeMetadataKey = "primary_provider_type";
    private const string PrimaryProviderNameMetadataKey = "primary_provider_name";
    private const string PrimaryCredentialKeyMetadataKey = "primary_credential_key";

    private static readonly Action<ILogger, string, Exception?> MfaFactorVerificationRejected =
        LoggerMessage.Define<string>(
            LogLevel.Debug,
            new EventId(1000, nameof(MfaFactorVerificationRejected)),
            "MFA factor verification rejected. Reason={Reason}");

    private static readonly Action<ILogger, Guid, string, Exception?> MfaHandshakeFactorVerificationRejected =
        LoggerMessage.Define<Guid, string>(
            LogLevel.Debug,
            new EventId(1001, nameof(MfaHandshakeFactorVerificationRejected)),
            "MFA factor verification rejected for handshake. UserId={UserId} Reason={Reason}");

    private static readonly Action<ILogger, Guid, string?, Exception?> MfaHandshakeOperationFailed =
        LoggerMessage.Define<Guid, string?>(
            LogLevel.Warning,
            new EventId(1002, nameof(MfaHandshakeOperationFailed)),
            "MFA handshake operation failed. UserId={UserId} FailureReason={FailureReason}");

    private readonly IAuthenticationPipeline _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
    private readonly IAuthenticationHandshakeService _handshakeService = handshakeService ?? throw new ArgumentNullException(nameof(handshakeService));
    private readonly IMfaPolicyEvaluator _policyEvaluator = policyEvaluator ?? throw new ArgumentNullException(nameof(policyEvaluator));
    private readonly MfaOrchestrationOptions _globalOptions = globalOptions?.Value ?? new MfaOrchestrationOptions();
    private readonly ILogger<AuthenticationOrchestrator> _logger = logger ?? NullLogger<AuthenticationOrchestrator>.Instance;

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
            return await CreateMfaRequiredResultAsync(response.User, response, policyEvaluation, options, context, primaryAssertion, cancellationToken);
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
            MfaFactorVerificationRejected(_logger, "handshake_not_found", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Handshake not found.");
        }

        if (!TryResolveRequiredFactor(handshake, factorType, out var resolvedFactorType))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "invalid_factor_type", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Invalid factor type.");
        }

        if (handshake.VerifiedFactors.Any(verifiedFactor => FactorsMatch(verifiedFactor, resolvedFactorType)))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "factor_already_verified", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Factor already verified.");
        }

        if (!IsAssertionAuthorizedForFactor(assertion, resolvedFactorType))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "assertion_not_authorized_for_factor", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Factor verification failed.");
        }

        if (IsSameCredentialAsPrimary(handshake, assertion))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "factor_reuses_primary_credential", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Factor verification failed.");
        }

        var factorContext = context with { UserId = handshake.UserId };
        var response = await _pipeline.LoginAsync(factorContext, assertion, cancellationToken);
        if (!response.Succeeded || response.User?.Id != handshake.UserId)
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "factor_authentication_failed", null);
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
            new VerifyAuthenticationHandshakeRequest(handshakeToken, resolvedFactorType, metadata, factorContext),
            cancellationToken);

        if (!result.Succeeded || result.Value == null)
        {
            MfaHandshakeOperationFailed(_logger, handshake.UserId, result.FailureReason, null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: GetHandshakeVerificationFailureMessage(result.FailureCode));
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
        AuthenticationContext context,
        IAuthenticationAssertion primaryAssertion,
        CancellationToken cancellationToken)
    {
        var requiredFactors = ResolveRequiredFactors(policyEvaluation, response.Claims, options.ProviderFactorsClaimName);
        if (requiredFactors.Count == 0)
        {
            MfaHandshakeOperationFailed(_logger, user.Id, "no_factors_configured", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: "MFA is required but no factors are configured.");
        }

        var result = await _handshakeService.CreateHandshakeAsync(
            new CreateAuthenticationHandshakeRequest(user.Id, requiredFactors, BuildClaimMetadata(response.Claims, primaryAssertion), context with { UserId = user.Id }),
            cancellationToken);

        if (!result.Succeeded)
        {
            MfaHandshakeOperationFailed(_logger, user.Id, result.FailureReason, null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: GetHandshakeCreationFailureMessage(result.FailureCode));
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

    private static bool IsSameCredentialAsPrimary(AuthenticationHandshake handshake, IAuthenticationAssertion assertion)
    {
        if (handshake.Metadata == null || assertion is not ICredentialKeyAuthenticationAssertion credentialAssertion)
        {
            return false;
        }

        return handshake.Metadata.TryGetValue(PrimaryProviderTypeMetadataKey, out var providerType)
            && handshake.Metadata.TryGetValue(PrimaryProviderNameMetadataKey, out var providerName)
            && handshake.Metadata.TryGetValue(PrimaryCredentialKeyMetadataKey, out var credentialKey)
            && string.Equals(providerType, assertion.ProviderIdentity.Type.Value, StringComparison.OrdinalIgnoreCase)
            && string.Equals(providerName, assertion.ProviderIdentity.Name, StringComparison.OrdinalIgnoreCase)
            && string.Equals(credentialKey, credentialAssertion.CredentialKey, StringComparison.Ordinal);
    }

    private static Dictionary<string, string> BuildClaimMetadata(IDictionary<string, string>? claims, IAuthenticationAssertion primaryAssertion)
    {
        var metadata = claims?.ToDictionary(claim => $"claim:{claim.Key}", claim => claim.Value) ?? [];
        metadata[PrimaryProviderTypeMetadataKey] = primaryAssertion.ProviderIdentity.TypeValueOrUnknown;
        metadata[PrimaryProviderNameMetadataKey] = primaryAssertion.ProviderIdentity.Name;
        if (primaryAssertion is ICredentialKeyAuthenticationAssertion credentialAssertion)
        {
            metadata[PrimaryCredentialKeyMetadataKey] = credentialAssertion.CredentialKey;
        }

        return metadata;
    }

    private static Dictionary<string, string> ExtractClaims(IDictionary<string, string>? metadata)
    {
        return metadata?
            .Where(kvp => kvp.Key.StartsWith("claim:", StringComparison.Ordinal))
            .ToDictionary(kvp => kvp.Key[6..], kvp => kvp.Value) ?? [];
    }

    private static string GetHandshakeVerificationFailureMessage(AshlarFailureCode? failureCode)
    {
        return failureCode?.Value switch
        {
            AshlarFailureCodes.EmptyTokenValue => "Handshake token is required.",
            AshlarFailureCodes.HandshakeNotFoundValue => "Handshake not found.",
            AshlarFailureCodes.HandshakeRevokedValue => "Handshake is no longer valid.",
            AshlarFailureCodes.HandshakeExpiredValue => "Handshake has expired.",
            AshlarFailureCodes.HandshakeAlreadyCompletedValue => "Handshake has already been completed.",
            AshlarFailureCodes.RateLimitExceededValue => "Rate limit exceeded.",
            AshlarFailureCodes.InvalidFactorTypeValue => "Invalid factor type.",
            AshlarFailureCodes.FactorAlreadyVerifiedValue => "Factor already verified.",
            AshlarFailureCodes.InvalidMetadataValue => "Invalid metadata.",
            _ => "Factor verification failed."
        };
    }

    private static string GetHandshakeCreationFailureMessage(AshlarFailureCode? failureCode)
    {
        return failureCode?.Value switch
        {
            AshlarFailureCodes.NoFactorsSpecifiedValue => "MFA is required but no factors are configured.",
            AshlarFailureCodes.InvalidMetadataValue => "Invalid metadata.",
            _ => "Failed to create MFA handshake."
        };
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
