using System.Text.Json;
using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Authentication;

/// <summary>
/// Coordinates provider authentication, MFA policy evaluation, and handshake issuance.
/// </summary>
internal sealed class AuthenticationOrchestrator : IAuthenticationOrchestrator
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

    private readonly IAuthenticationPipeline _pipeline;
    private readonly IAuthenticationFactorPipeline _factorPipeline;
    private readonly IAuthenticationHandshakeService _handshakeService;
    private readonly IAuthenticationHandshakeOrchestrationService _handshakeCreationService;
    private readonly IAuthenticationHandshakeCompletionService _handshakeCompletionService;
    private readonly IMfaPolicyEvaluator _policyEvaluator;
    private readonly IAuthenticationProviderRegistry _providerRegistry;
    private readonly MfaOrchestrationOptions _globalOptions;
    private readonly IServiceProvider? _serviceProvider;
    private readonly ILogger<AuthenticationOrchestrator> _logger;

    internal AuthenticationOrchestrator(
        IAuthenticationPipeline pipeline,
        IAuthenticationFactorPipeline factorPipeline,
        IAuthenticationHandshakeOrchestrationService handshakeService,
        IAuthenticationHandshakeCompletionService handshakeCompletionService,
        IMfaPolicyEvaluator policyEvaluator,
        IAuthenticationProviderRegistry providerRegistry,
        AuthenticationOrchestratorDependencies? dependencies = null)
        : this(pipeline, factorPipeline, handshakeService, handshakeService, handshakeCompletionService, policyEvaluator, providerRegistry, dependencies)
    {
    }

    internal AuthenticationOrchestrator(
        IAuthenticationPipeline pipeline,
        IAuthenticationFactorPipeline factorPipeline,
        IAuthenticationHandshakeService handshakeService,
        IAuthenticationHandshakeOrchestrationService handshakeCreationService,
        IAuthenticationHandshakeCompletionService handshakeCompletionService,
        IMfaPolicyEvaluator policyEvaluator,
        IAuthenticationProviderRegistry providerRegistry,
        AuthenticationOrchestratorDependencies? dependencies = null)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _factorPipeline = factorPipeline ?? throw new ArgumentNullException(nameof(factorPipeline));
        _handshakeService = handshakeService ?? throw new ArgumentNullException(nameof(handshakeService));
        _handshakeCreationService = handshakeCreationService ?? throw new ArgumentNullException(nameof(handshakeCreationService));
        _handshakeCompletionService = handshakeCompletionService ?? throw new ArgumentNullException(nameof(handshakeCompletionService));
        _policyEvaluator = policyEvaluator ?? throw new ArgumentNullException(nameof(policyEvaluator));
        _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));

        var validatedDependencies = ValidateDependencies(dependencies);
        _globalOptions = validatedDependencies.GlobalOptions?.Value ?? new MfaOrchestrationOptions();
        _serviceProvider = validatedDependencies.ServiceProvider;
        _logger = validatedDependencies.Logger ?? NullLogger<AuthenticationOrchestrator>.Instance;
    }

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
            Claims: response.Claims,
            CredentialUpdatePersisted: response.CredentialUpdatePersisted)
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };
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

        var beginRequest = new BeginAuthenticationHandshakeVerificationRequest(handshakeToken, context);
        var beginResult = await _handshakeService.BeginVerificationAsync(beginRequest, cancellationToken);
        if (!beginResult.Succeeded || beginResult.Value == null)
        {
            MfaFactorVerificationRejected(_logger, beginResult.FailureReason ?? "handshake_verification_failed", null);
            return CreateHandshakeFailureResult(beginResult.FailureCode);
        }

        var handshake = beginResult.Value;
        if (!TryGetFactorProvider(assertion, out var factorProvider) ||
            !TryResolveRequiredFactor(handshake, factorType, factorProvider, out var resolvedFactorType))
        {
            MfaHandshakeFactorVerificationRejected(_logger, handshake.UserId, "invalid_factor_type", null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: "Invalid factor type.");
        }

        var assertionFailure = ValidateFactorAssertion(handshake, assertion);
        if (assertionFailure != null)
        {
            return assertionFailure;
        }

        var factorContext = context with { UserId = handshake.UserId };
        var verificationRequest = new VerifyAuthenticationHandshakeRequest(handshakeToken, resolvedFactorType, Context: factorContext);

        var response = await _factorPipeline.VerifyFactorAsync(factorContext, assertion, cancellationToken);
        if (!response.Succeeded || response.User?.Id != handshake.UserId)
        {
            return CreateFactorAuthenticationFailureResult(handshake.UserId, response);
        }

        var metadata = CreateFactorVerificationMetadata(response);
        var result = await _handshakeCompletionService.CompleteFactorVerificationAsync(verificationRequest with { Metadata = metadata }, cancellationToken);

        if (!result.Succeeded || result.Value == null)
        {
            MfaHandshakeOperationFailed(_logger, handshake.UserId, result.FailureReason, null);
            return new MfaAuthenticationResult(MfaAuthenticationStatus.Failed, ErrorMessage: GetHandshakeVerificationFailureMessage(result.FailureCode));
        }

        return CreateResultFromHandshake(result.Value, response.User, handshakeToken, response.CredentialUpdatePersisted);
    }

    private MfaAuthenticationResult CreateFactorAuthenticationFailureResult(Guid userId, AuthenticationResponse response)
    {
        MfaHandshakeFactorVerificationRejected(_logger, userId, "factor_authentication_failed", null);
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

    private static Dictionary<string, string> CreateFactorVerificationMetadata(AuthenticationResponse response)
    {
        Dictionary<string, string> metadata = [];
        if (response.Claims == null)
        {
            return metadata;
        }

        foreach (var claim in response.Claims)
        {
            metadata[$"claim:{claim.Key}"] = JsonSerializer.Serialize(claim.Value);
        }

        return metadata;
    }

    private static MfaAuthenticationResult CreateHandshakeFailureResult(AshlarFailureCode? failureCode)
    {
        var status = failureCode?.Value == AshlarFailureCodes.RateLimitExceededValue
            ? MfaAuthenticationStatus.RateLimited
            : MfaAuthenticationStatus.Failed;
        return new MfaAuthenticationResult(status, ErrorMessage: GetHandshakeVerificationFailureMessage(failureCode));
    }

    private static MfaAuthenticationResult CreateResultFromHandshake(AuthenticationHandshake handshake, IUser user, string? handshakeToken, bool credentialUpdatePersisted)
    {
        if (handshake.IsCompleted)
        {
            var claims = ExtractClaims(handshake.Metadata);

            return new MfaAuthenticationResult(
                MfaAuthenticationStatus.Succeeded,
                User: user,
                Claims: claims,
                FreshMfaSatisfied: true,
                CredentialUpdatePersisted: credentialUpdatePersisted)
            {
                RememberedDeviceCreationProof = FreshMfaProof.Instance,
                SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance,
                StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
            };
        }

        return new MfaAuthenticationResult(
            MfaAuthenticationStatus.HandshakeIncomplete,
            User: user,
            HandshakeToken: handshakeToken,
            RequiredFactors: handshake.RequiredFactors
                .Where(requiredFactor => !handshake.VerifiedFactors.Any(verifiedFactor => AuthenticationFactorTypes.Matches(requiredFactor, verifiedFactor)))
                .ToArray(),
            CredentialUpdatePersisted: credentialUpdatePersisted);
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
                Claims: response.Claims,
                CredentialUpdatePersisted: response.CredentialUpdatePersisted)
            {
                SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
            };
        }

        var result = await _handshakeCreationService.CreateHandshakeAsync(
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
            created.Handshake.RequiredFactors,
            CredentialUpdatePersisted: response.CredentialUpdatePersisted);
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
        metadata[PrimaryProviderTypeMetadataKey] = primaryAssertion.ProviderIdentity.StorageTypeValue;
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

    private bool TryGetFactorProvider(
        IAuthenticationAssertion assertion,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out ISecondaryAuthenticationFactorProvider? factorProvider)
    {
        if (!_providerRegistry.TryGetProvider(assertion, out var provider) ||
            provider is not ISecondaryAuthenticationFactorProvider secondaryProvider)
        {
            factorProvider = null;
            return false;
        }

        factorProvider = secondaryProvider;
        return true;
    }

    private MfaAuthenticationResult? ValidateFactorAssertion(
        AuthenticationHandshake handshake,
        IAuthenticationAssertion assertion)
    {
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

    private static bool TryResolveRequiredFactor(
        AuthenticationHandshake handshake,
        string requestedFactorType,
        ISecondaryAuthenticationFactorProvider factorProvider,
        out string resolvedFactorType)
    {
        var pendingFactors = handshake.RequiredFactors
            .Where(requiredFactor => !handshake.VerifiedFactors.Any(verifiedFactor => AuthenticationFactorTypes.Matches(requiredFactor, verifiedFactor)))
            .ToArray();

        var requiredFactor = pendingFactors.FirstOrDefault(requiredFactor =>
            AuthenticationFactorTypes.Matches(requiredFactor, requestedFactorType) &&
            factorProvider.CanSatisfyFactor(requiredFactor));

        requiredFactor ??= factorProvider is IBackupAuthenticationFactorProvider backupProvider &&
            AuthenticationFactorTypes.Matches(factorProvider.FactorType, requestedFactorType)
            ? pendingFactors.FirstOrDefault(backupProvider.CanSatisfyBackupFactor)
            : null;

        resolvedFactorType = requiredFactor ?? string.Empty;
        return requiredFactor != null;
    }
}

/// <summary>
/// Optional dependencies for <see cref="AuthenticationOrchestrator"/>.
/// </summary>
/// <param name="GlobalOptions">The global orchestration options.</param>
/// <param name="ServiceProvider">The service provider used for opt-in remembered MFA device support.</param>
/// <param name="Logger">Optional logger for authentication orchestration diagnostics.</param>
internal sealed record AuthenticationOrchestratorDependencies(
    IOptions<MfaOrchestrationOptions>? GlobalOptions = null,
    IServiceProvider? ServiceProvider = null,
    ILogger<AuthenticationOrchestrator>? Logger = null);
