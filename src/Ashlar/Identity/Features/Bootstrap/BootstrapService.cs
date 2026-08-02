using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Identity.Features.Bootstrap;

/// <summary>
/// Creates the first administrator for an uninitialized Ashlar installation.
/// </summary>
/// <param name="dependencies">The dependencies required by the bootstrap workflow.</param>
/// <param name="options">Configures the setup secret and first-admin grants.</param>
internal sealed class BootstrapService(
    BootstrapDependencies dependencies,
    IOptions<BootstrapOptions>? options = null)
    : IBootstrapService
{
    private readonly BootstrapDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly IOptions<BootstrapOptions> _options = options ?? Options.Create(new BootstrapOptions());
    private readonly IAuthorizationGrantBootstrapService? _grantService = ValidateGrantService(dependencies.GrantService, options?.Value ?? new BootstrapOptions());
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);
    private readonly AuthenticationRateLimitChecker _rateLimitChecker = new(dependencies.RateLimiter);

    /// <summary>
    /// Checks whether first-admin bootstrap has already initialized the installation.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel bootstrap status lookup.</param>
    /// <returns>Current bootstrap initialization state.</returns>
    public Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        return _dependencies.StateRepository.GetBootstrapStatusAsync(cancellationToken);
    }

    /// <summary>
    /// Creates the first administrator for an uninitialized installation.
    /// </summary>
    /// <param name="request">The first-admin details and setup secret supplied by the operator. Do not log the setup secret.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token that can cancel first-admin bootstrap.</param>
    /// <returns>The created administrator user ID when bootstrap succeeds; otherwise a failure describing why bootstrap was rejected.</returns>
    public async Task<Result<BootstrapFirstAdminResult>> BootstrapFirstAdminAsync(BootstrapFirstAdminRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var email = IdentityNormalization.SanitizeEmailForDelivery(request.Email);

        if (await GetStatusAsync(cancellationToken) == BootstrapStatus.Initialized)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapRequested,
                Outcome = SecurityEventOutcomes.Failure,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Properties = AddEmailIfEnabled([], email)
            }, cancellationToken);
            return Result.Failure<BootstrapFirstAdminResult>(AshlarFailureCodes.AlreadyInitialized);
        }

        if (!await CheckRateLimitAsync(request.TenantId, context, cancellationToken))
        {
            return Result.Failure<BootstrapFirstAdminResult>(AshlarFailureCodes.RateLimited);
        }

        if (!await AuthorizeSetupAsync(
            request.SetupSecret,
            request.TenantId,
            request.Audit,
            context,
            cancellationToken))
        {
            return Result.Failure<BootstrapFirstAdminResult>(AshlarFailureCodes.InvalidSecret);
        }

        return await CompleteFirstAdminBootstrapAsync(request, email, context, cancellationToken);
    }

    private async Task<Result<BootstrapFirstAdminResult>> CompleteFirstAdminBootstrapAsync(BootstrapFirstAdminRequest request, string email, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        if (await GetStatusAsync(cancellationToken) == BootstrapStatus.Initialized)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Context = context
            }, cancellationToken);
            return Result.Failure<BootstrapFirstAdminResult>(AshlarFailureCodes.AlreadyInitialized);
        }

        var now = _dependencies.TimeProvider.GetUtcNow();
        var grants = _options.Value.Grants;
        var authorizationGrantService = _grantService;
        if (grants.Count > 0 && authorizationGrantService is null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                TenantId = request.TenantId,
                Audit = request.Audit,
                Context = context,
                FailureReason = AshlarFailureCodes.InvalidConfiguration.Value
            }, cancellationToken);

            return Result.Failure<BootstrapFirstAdminResult>(AshlarFailureCodes.InvalidConfiguration);
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);
        var createdUser = await CreateOrActivateFirstAdminUserAsync(email, request.UserName, request.TenantId, now, cancellationToken);
        var userId = createdUser.UserId;

        if (authorizationGrantService is not null)
        {
            foreach (var template in grants)
            {
                var grantResult = await authorizationGrantService.CreateGrantAsync(new CreateAuthorizationGrantRequest(
                    userId, CreateBootstrapGrantAudit(request.Audit, context), template.TenantId,
                    new AuthorizationGrantSpecification
                    {
                        ScopeType = template.ScopeType,
                        ScopeId = template.ScopeId,
                        Role = template.Role,
                        Permission = template.Permission
                    }), cancellationToken);

                if (!grantResult.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    await _securityEvents.RecordAsync(new SecurityEventDescriptor
                    {
                        EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                        Outcome = SecurityEventOutcomes.Failure,
                        FailureReason = grantResult.GetFailure().Code.Value,
                        UserId = userId,
                        TenantId = request.TenantId,
                        Audit = request.Audit,
                        Context = context
                    }, cancellationToken);
                    return Result.Failure<BootstrapFirstAdminResult>(grantResult.GetFailure());
                }
            }
        }

        var initialized = await _dependencies.StateRepository.MarkAsInitializedAsync(userId, now, cancellationToken);
        if (!initialized)
        {
            // This should only happen if someone else initialized the system concurrently.
            await transaction.RollbackAsync(cancellationToken);
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Context = context
            }, cancellationToken);
            return Result.Failure<BootstrapFirstAdminResult>(AshlarFailureCodes.AlreadyInitialized);
        }

        if (createdUser.IsNewUser)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.UserCreated,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = request.TenantId,
                Audit = request.Audit,
                Context = context
            }, cancellationToken);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.BootstrapCompleted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = request.TenantId,
            Audit = request.Audit,
            Context = context
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            var notifiedUser = await _dependencies.UserRepository.GetUserByIdAsync(userId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.BootstrapCompleted, notifiedUser, now, context: context, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        var authenticatedUser = new BootstrapAuthenticatedUser(userId, email, request.TenantId);
        return Result.Success(new BootstrapFirstAdminResult(userId, CreateSessionIssuanceResult(authenticatedUser)));
    }

    private async Task<bool> CheckRateLimitAsync(Guid? tenantId, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        var sourceBucket = AuthenticationRateLimitDimensions.Source(context);
        var rateLimit = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(
            "bootstrap-first-admin",
            AuthenticationRateLimitDimensions.DimensionName(sourceBucket),
            sourceBucket,
            _options.Value.AttemptRateLimit)
        {
            Context = context,
            TenantId = tenantId
        }, cancellationToken);

        if (rateLimit.IsAllowed)
        {
            return true;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.BootstrapRequested,
            Outcome = SecurityEventOutcomes.Failure,
            TenantId = tenantId,
            Context = context,
            FailureReason = AshlarFailureCodes.RateLimited.Value
        }, cancellationToken);
        return false;
    }

    private MfaAuthenticationResult CreateSessionIssuanceResult(IUser user)
    {
        return new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user)
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.CreatePrimary(user.Id, null, _dependencies.TimeProvider.GetUtcNow())
        };
    }

    private static IAuthorizationGrantBootstrapService? ValidateGrantService(IAuthorizationGrantBootstrapService? grantService, BootstrapOptions options)
    {
        if (options.Grants.Count > 0 && grantService is null)
        {
            throw new InvalidOperationException("Bootstrap grants require Ashlar's built-in authorization services. Register AddAshlarAuthorization or remove BootstrapOptions.Grants.");
        }

        return grantService;
    }

    private async Task<BootstrapUser> CreateOrActivateFirstAdminUserAsync(
        string email,
        string? requestedUserName,
        Guid? tenantId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var user = await _dependencies.UserRepository.GetUserByEmailAsync(email, tenantId, cancellationToken);
        if (user == null)
        {
            var userId = Guid.NewGuid();
            await _dependencies.UserRepository.CreateUserAsync(new AshlarUser
            {
                Id = userId,
                DisplayEmail = email,
                Name = requestedUserName,
                AccountState = UserAccountState.Active,
                EmailVerifiedAt = now,
                TenantId = tenantId
            }, cancellationToken);
            return new BootstrapUser(userId, IsNewUser: true);
        }

        if (!user.CanSignIn() || !user.EmailVerifiedAt.HasValue)
        {
            await _dependencies.UserRepository.UpdateUserAsync(new AshlarUser
            {
                Id = user.Id,
                DisplayEmail = user.DisplayEmail,
                Name = requestedUserName ?? user.Name,
                AccountState = UserAccountState.Active,
                EmailVerifiedAt = user.EmailVerifiedAt ?? now,
                TenantId = tenantId
            }, cancellationToken);
        }

        return new BootstrapUser(user.Id, IsNewUser: false);
    }

    private async Task<bool> AuthorizeSetupAsync(
        string? setupSecret,
        Guid? tenantId,
        AuditContext? audit,
        AuthenticationContext? context,
        CancellationToken cancellationToken)
    {
        var bootstrapOptions = _options.Value;
        var failureReason = GetSetupAuthorizationFailureReason(bootstrapOptions, setupSecret);
        if (failureReason is null)
        {
            return true;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.BootstrapRequested,
            Outcome = SecurityEventOutcomes.Failure,
            TenantId = tenantId,
            Audit = audit,
            Context = context,
            FailureReason = failureReason
        }, cancellationToken);

        return false;
    }

    private static AuditContext CreateBootstrapGrantAudit(AuditContext? audit, AuthenticationContext? context)
    {
        var items = audit?.Items is null
            ? []
            : new Dictionary<string, string>(audit.Items);
        items["system"] = "bootstrap";

        return new AuditContext(
            ActorUserId: audit?.ActorUserId ?? context?.UserId,
            IpAddress: audit?.IpAddress ?? context?.IpAddress,
            UserAgent: audit?.UserAgent ?? context?.UserAgent,
            CorrelationId: audit?.CorrelationId ?? context?.CorrelationId,
            Items: items);
    }

    private string? GetSetupAuthorizationFailureReason(BootstrapOptions bootstrapOptions, string? setupSecret)
    {
        if (string.IsNullOrWhiteSpace(bootstrapOptions.SetupSecret)
            || !SecureTokenHashing.TryHashToken(_dependencies.TokenContext.Hasher, bootstrapOptions.SetupSecret, out var configuredHash))
        {
            return SecurityEventFailureReasons.BootstrapSetupAuthorizationMissing;
        }

        if (!SecureTokenHashing.TryHashToken(_dependencies.TokenContext.Hasher, setupSecret, out var suppliedHash))
        {
            return SecurityEventFailureReasons.BootstrapSetupAuthorizationInvalid;
        }

        return FixedTimeEquals(suppliedHash, configuredHash)
            ? null
            : SecurityEventFailureReasons.BootstrapSetupAuthorizationInvalid;
    }

    private static bool FixedTimeEquals(string suppliedHash, string configuredHash)
    {
        var suppliedBytes = Encoding.UTF8.GetBytes(suppliedHash);
        var configuredBytes = Encoding.UTF8.GetBytes(configuredHash);
        if (suppliedBytes.Length != configuredBytes.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(suppliedBytes, configuredBytes);
    }

    private Dictionary<string, string> AddEmailIfEnabled(Dictionary<string, string> properties, string email)
    {
        if (_options.Value.StoreEmailInAudit)
        {
            properties["email"] = email;
        }

        return properties;
    }

    private sealed record BootstrapUser(Guid UserId, bool IsNewUser);
    private sealed record BootstrapAuthenticatedUser(
        Guid Id,
        string DisplayEmail,
        Guid? TenantId,
        string? Name = null,
        UserAccountState AccountState = UserAccountState.Active,
        DateTimeOffset? EmailVerifiedAt = null) : ITenantUser;
}
