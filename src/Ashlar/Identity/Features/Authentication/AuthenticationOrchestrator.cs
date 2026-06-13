using System.Text.Json;
using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Authentication;

/// <summary>
/// Provides authentication orchestrator behavior.
/// </summary>
/// <param name="pipeline">The pipeline value.</param>
/// <param name="factorPipeline">The factor pipeline value.</param>
/// <param name="handshakeService">The handshake service value.</param>
/// <param name="policyEvaluator">The policy evaluator value.</param>
/// <param name="providerRegistry">The provider registry value.</param>
/// <param name="dependencies">Optional operational dependencies.</param>
public sealed class AuthenticationOrchestrator(
    IAuthenticationPipeline pipeline,
    IAuthenticationFactorPipeline factorPipeline,
    IAuthenticationHandshakeService handshakeService,
    IMfaPolicyEvaluator policyEvaluator,
    IAuthenticationProviderRegistry providerRegistry,
    AuthenticationOrchestratorDependencies? dependencies = null)
    : IAuthenticationOrchestrator
{
    private const string PrimaryProviderTypeMetadataKey = "primary_provider_type";
    private const string PrimaryProviderNameMetadataKey = "primary_provider_name";
    private const string PrimaryCredentialKeyMetadataKey = "primary_credential_key";
    private const string AuthenticationFailedMessage = "Authentication failed.";
    private const string RateLimitExceededMessage = "Rate limit exceeded.";
    private const string FactorVerificationFailedMessage = "Factor verification failed.";

    private static AuthenticationOrchestratorDependencies ValidateDependencies(AuthenticationOrchestratorDependencies? dependencies)
    {
        return dependencies ?? new AuthenticationOrchestratorDependencies();
    }

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
    private readonly IAuthenticationFactorPipeline _factorPipeline = factorPipeline ?? throw new ArgumentNullException(nameof(factorPipeline));
    private readonly IAuthenticationHandshakeService _handshakeService = handshakeService ?? throw new ArgumentNullException(nameof(handshakeService));
    private readonly IMfaPolicyEvaluator _policyEvaluator = policyEvaluator ?? throw new ArgumentNullException(nameof(policyEvaluator));
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly MfaOrchestrationOptions _globalOptions = ValidateDependencies(dependencies).GlobalOptions?.Value ?? new MfaOrchestrationOptions();
    private readonly IServiceProvider? _serviceProvider = ValidateDependencies(dependencies).ServiceProvider;
    private readonly ILogger<AuthenticationOrchestrator> _logger = ValidateDependencies(dependencies).Logger ?? NullLogger<AuthenticationOrchestrator>.Instance;

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
                AuthenticationStatus.Disabled => new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: AuthenticationFailedMessage),
                AuthenticationStatus.RateLimited => new MfaAuthenticationResult(MfaAuthenticationStatus.RateLimited, response.User, ErrorMessage: RateLimitExceededMessage),
                _ => new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: AuthenticationFailedMessage)
            };
        }

        if (response.User == null)
        {
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: AuthenticationFailedMessage);
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
        string? handshakeToken,
        string factorType,
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(factorType);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        var verificationRequest = new VerifyAuthenticationHandshakeRequest(handshakeToken, factorType, Context: context);
        var beginResult = await _handshakeService.BeginFactorVerificationAsync(verificationRequest, cancellationToken);
        if (!beginResult.Succeeded || beginResult.Value == null)
        {
            MfaFactorVerificationRejected(_logger, beginResult.FailureReason ?? "handshake_verification_failed", null);
            return CreateHandshakeFailureResult(beginResult.FailureCode);
        }

        var handshake = beginResult.Value;
        if (!TryResolveRequiredFactor(handshake, factorType, out var resolvedFactorType))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "invalid_factor_type", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Invalid factor type.");
        }

        var assertionFailure = ValidateFactorAssertion(handshake, resolvedFactorType, assertion);
        if (assertionFailure != null)
        {
            return assertionFailure;
        }

        var factorContext = context with { UserId = handshake.UserId };
        verificationRequest = verificationRequest with { FactorType = resolvedFactorType, Context = factorContext };

        var response = await _factorPipeline.VerifyFactorAsync(factorContext, assertion, cancellationToken);
        if (!response.Succeeded || response.User?.Id != handshake.UserId)
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "factor_authentication_failed", null);
            var errorMessage = response.Status switch
            {
                AuthenticationStatus.Disabled => AuthenticationFailedMessage,
                AuthenticationStatus.RateLimited => RateLimitExceededMessage,
                _ => FactorVerificationFailedMessage
            };
            var status = response.Status == AuthenticationStatus.RateLimited
                ? MfaAuthenticationStatus.RateLimited
                : MfaAuthenticationStatus.Failed;
            return new MfaAuthenticationResult(status, ErrorMessage: errorMessage);
        }

        // Capture any new claims from this factor
        Dictionary<string, string> metadata = [];
        if (response.Claims != null)
        {
            foreach (var claim in response.Claims)
            {
                metadata[$"claim:{claim.Key}"] = JsonSerializer.Serialize(claim.Value);
            }
        }

        var result = await _handshakeService.CompleteFactorVerificationAsync(verificationRequest with { Metadata = metadata }, cancellationToken);

        if (!result.Succeeded || result.Value == null)
        {
            MfaHandshakeOperationFailed(_logger, handshake.UserId, result.FailureReason, null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: GetHandshakeVerificationFailureMessage(result.FailureCode));
        }

        return CreateResultFromHandshake(result.Value, response.User, handshakeToken);
    }

    private static MfaAuthenticationResult CreateHandshakeFailureResult(AshlarFailureCode? failureCode)
    {
        var status = failureCode?.Value == AshlarFailureCodes.RateLimitExceededValue
            ? MfaAuthenticationStatus.RateLimited
            : MfaAuthenticationStatus.Failed;
        return new MfaAuthenticationResult(status, ErrorMessage: GetHandshakeVerificationFailureMessage(failureCode));
    }

    private static MfaAuthenticationResult CreateResultFromHandshake(AuthenticationHandshake handshake, IUser user, string? handshakeToken)
    {
        if (handshake.IsCompleted)
        {
            var claims = ExtractClaims(handshake.Metadata);

            return new MfaAuthenticationResult(
                MfaAuthenticationStatus.Succeeded,
                User: user,
                Claims: claims,
                FreshMfaSatisfied: true);
        }

        return new MfaAuthenticationResult(
            MfaAuthenticationStatus.HandshakeIncomplete,
            User: user,
            HandshakeToken: handshakeToken,
            RequiredFactors: handshake.RequiredFactors
                .Where(requiredFactor => !handshake.VerifiedFactors.Any(verifiedFactor => AuthenticationFactorTypes.Matches(requiredFactor, verifiedFactor)))
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

        if (response.Succeeded
            && response.Status != AuthenticationStatus.MfaRequired
            && policyEvaluation.IsMfaRequired
            && await TryValidateRememberedMfaDeviceAsync(user, options, context, cancellationToken))
        {
            return new MfaAuthenticationResult(
                MfaAuthenticationStatus.Succeeded,
                user,
                Claims: response.Claims);
        }

        var result = await _handshakeService.CreateHandshakeAsync(
            new CreateAuthenticationHandshakeRequest(user.Id, requiredFactors, BuildClaimMetadata(response.Claims, primaryAssertion), context with { UserId = user.Id }),
            cancellationToken);

        if (!result.TryGetValue(out var created))
        {
            MfaHandshakeOperationFailed(_logger, user.Id, result.FailureReason, null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, response.User, ErrorMessage: GetHandshakeCreationFailureMessage(result.FailureCode));
        }

        return new MfaAuthenticationResult(
            MfaAuthenticationStatus.MfaRequired,
            user,
            created.Token,
            created.Handshake.RequiredFactors);
    }

    private async Task<bool> TryValidateRememberedMfaDeviceAsync(
        IUser user,
        MfaOrchestrationOptions options,
        AuthenticationContext context,
        CancellationToken cancellationToken)
    {
        if (!options.EnableRememberedMfaDevices || _serviceProvider == null)
        {
            return false;
        }

        var rememberedMfaDeviceService = _serviceProvider.GetService<IRememberedMfaDeviceService>();
        if (rememberedMfaDeviceService == null)
        {
            return false;
        }

        if (!context.TryGetRememberedMfaDeviceToken(out var token))
        {
            return false;
        }

        var result = await rememberedMfaDeviceService.ValidateAsync(
            user.Id,
            new ValidateRememberedMfaDeviceRequest(token)
            {
                Tenant = context.TenantId.HasValue ? new TenantContext(context.TenantId.Value) : null,
                Audit = new AuditContext(
                    ActorUserId: user.Id,
                    IpAddress: context.IpAddress,
                    UserAgent: context.UserAgent,
                    CorrelationId: context.CorrelationId)
            },
            cancellationToken);

        return result.Succeeded;
    }

    private static HashSet<string> ResolveRequiredFactors(
        MfaPolicyEvaluation policyEvaluation,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? claims,
        string providerFactorsClaimName)
    {
        var requiredFactors = new HashSet<string>(
            NormalizeRequiredFactors(policyEvaluation.Requirement?.RequiredFactors),
            StringComparer.OrdinalIgnoreCase);

        if (requiredFactors.Count == 0 &&
            claims?.TryGetValue(providerFactorsClaimName, out var providerFactors) == true &&
            providerFactors.Any(value => !string.IsNullOrWhiteSpace(value)))
        {
            requiredFactors.UnionWith(providerFactors
                .SelectMany(value => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
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

    private static Dictionary<string, string> BuildClaimMetadata(IReadOnlyDictionary<string, IReadOnlyList<string>>? claims, IAuthenticationAssertion primaryAssertion)
    {
        var metadata = claims?.ToDictionary(claim => $"claim:{claim.Key}", claim => JsonSerializer.Serialize(claim.Value)) ?? [];
        metadata[PrimaryProviderTypeMetadataKey] = primaryAssertion.ProviderIdentity.TypeValueOrUnknown;
        metadata[PrimaryProviderNameMetadataKey] = primaryAssertion.ProviderIdentity.Name;
        if (primaryAssertion is ICredentialKeyAuthenticationAssertion credentialAssertion)
        {
            metadata[PrimaryCredentialKeyMetadataKey] = credentialAssertion.CredentialKey;
        }

        return metadata;
    }

    private static Dictionary<string, IReadOnlyList<string>> ExtractClaims(IDictionary<string, string>? metadata)
    {
        return metadata?
            .Where(kvp => kvp.Key.StartsWith("claim:", StringComparison.Ordinal))
            .ToDictionary(
                kvp => kvp.Key[6..],
                kvp => (IReadOnlyList<string>)(JsonSerializer.Deserialize<string[]>(kvp.Value) ?? [])) ?? [];
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
            AshlarFailureCodes.RateLimitExceededValue => RateLimitExceededMessage,
            AshlarFailureCodes.InvalidFactorTypeValue => "Invalid factor type.",
            AshlarFailureCodes.FactorAlreadyVerifiedValue => "Factor already verified.",
            AshlarFailureCodes.InvalidMetadataValue => "Invalid metadata.",
            _ => FactorVerificationFailedMessage
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

    private bool IsAssertionAuthorizedForFactor(IAuthenticationAssertion assertion, string factorType)
    {
        if (!_providerRegistry.TryGetProvider(assertion, out var provider) ||
            provider is not ISecondaryAuthenticationFactorProvider factorProvider)
        {
            return false;
        }

        return factorProvider.CanSatisfyFactor(factorType);
    }

    private MfaAuthenticationResult? ValidateFactorAssertion(
        AuthenticationHandshake handshake,
        string resolvedFactorType,
        IAuthenticationAssertion assertion)
    {
        if (!IsAssertionAuthorizedForFactor(assertion, resolvedFactorType))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "assertion_not_authorized_for_factor", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: FactorVerificationFailedMessage);
        }

        if (IsSameCredentialAsPrimary(handshake, assertion))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "factor_reuses_primary_credential", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: FactorVerificationFailedMessage);
        }

        return null;
    }

    private static IEnumerable<string> NormalizeRequiredFactors(IEnumerable<string>? factors)
    {
        return factors?.Where(factor => !string.IsNullOrWhiteSpace(factor)).Select(factor => factor.Trim()) ?? [];
    }

    private static bool TryResolveRequiredFactor(AuthenticationHandshake handshake, string factorType, out string resolvedFactorType)
    {
        var requiredFactor = AuthenticationFactorTypes.Matches(factorType, AuthenticationFactorTypes.RecoveryCode)
            ? handshake.RequiredFactors.FirstOrDefault(requiredFactor =>
                !handshake.VerifiedFactors.Any(verifiedFactor => AuthenticationFactorTypes.Matches(requiredFactor, verifiedFactor)))
            : handshake.RequiredFactors.FirstOrDefault(requiredFactor => AuthenticationFactorTypes.Matches(requiredFactor, factorType));

        resolvedFactorType = requiredFactor ?? string.Empty;
        return requiredFactor != null;
    }
}

/// <summary>
/// Optional dependencies for <see cref="AuthenticationOrchestrator"/>.
/// </summary>
/// <param name="GlobalOptions">The global orchestration options.</param>
/// <param name="ServiceProvider">The service provider used for opt-in remembered MFA device support.</param>
/// <param name="Logger">The logger.</param>
public sealed record AuthenticationOrchestratorDependencies(
    IOptions<MfaOrchestrationOptions>? GlobalOptions = null,
    IServiceProvider? ServiceProvider = null,
    ILogger<AuthenticationOrchestrator>? Logger = null);
