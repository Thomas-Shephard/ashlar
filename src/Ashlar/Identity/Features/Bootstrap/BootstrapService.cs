using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Identity.Features.Bootstrap;

/// <summary>
/// Creates the first administrator for an uninitialized Ashlar installation.
/// </summary>
/// <param name="stateRepository">Reads and marks bootstrap initialization state.</param>
/// <param name="userRepository">Stores and retrieves first-admin users.</param>
/// <param name="transactionProvider">Creates transactions for the bootstrap workflow.</param>
/// <param name="tokenContext">Hashes setup secrets before comparison.</param>
/// <param name="auditContext">Provides time, audit, and notification dependencies.</param>
/// <param name="grantService">Optionally assigns configured grants to the first administrator.</param>
/// <param name="options">Configures the setup secret and first-admin grants.</param>
/// <param name="notificationService">Optionally sends bootstrap security notifications.</param>
/// <param name="rateLimiter">Optionally rate limits bootstrap attempts.</param>
internal sealed class BootstrapService(
    IBootstrapStateRepository stateRepository,
    IUserRepository userRepository,
    IAshlarTransactionProvider transactionProvider,
    SecureTokenContext tokenContext,
    IdentityAuditContext auditContext,
    IAuthorizationGrantService? grantService = null,
    IOptions<BootstrapOptions>? options = null,
    ISecurityNotificationService? notificationService = null,
    IAuthenticationRateLimiter? rateLimiter = null)
    : IBootstrapService
{
    private readonly IBootstrapStateRepository _stateRepository = stateRepository ?? throw new ArgumentNullException(nameof(stateRepository));
    private readonly IUserRepository _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    private readonly IdentityAuditContext _auditContext = auditContext ?? throw new ArgumentNullException(nameof(auditContext));
    private readonly IAuthorizationGrantService? _grantService = ValidateGrantService(grantService, options?.Value ?? new BootstrapOptions());
    private readonly IOptions<BootstrapOptions> _options = options ?? Options.Create(new BootstrapOptions());
    private readonly SecurityEventEmitter _securityEvents = new(auditContext.SecurityEventSink, auditContext.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(notificationService ?? auditContext.NotificationService);
    private readonly AuthenticationRateLimitChecker? _rateLimitChecker = rateLimiter == null ? null : new AuthenticationRateLimitChecker(rateLimiter);

    /// <summary>
    /// Gets whether the installation has already been initialized.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The current bootstrap status.</returns>
    public Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        return _stateRepository.GetBootstrapStatusAsync(cancellationToken);
    }

    /// <summary>
    /// Creates the first administrator for an uninitialized installation.
    /// </summary>
    /// <param name="request">The first-admin details and setup secret supplied by the operator.</param>
    /// <param name="context">Optional request context for auditing and notifications.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created administrator user ID when bootstrap succeeds; otherwise a failure describing why bootstrap was rejected.</returns>
    public async Task<Result<Guid>> BootstrapFirstAdminAsync(BootstrapFirstAdminRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var email = IdentityNormalization.SanitizeEmailForDelivery(request.Email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(email);

        if (await GetStatusAsync(cancellationToken) == BootstrapStatus.Initialized)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapRequested,
                Outcome = SecurityEventOutcomes.Failure,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Properties = AddEmailIfEnabled(new Dictionary<string, string>(), email)
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.AlreadyInitialized);
        }

        if (!await CheckRateLimitAsync(request.TenantId, context, cancellationToken))
        {
            return Result.Failure<Guid>(AshlarFailureCodes.RateLimited);
        }

        if (!await AuthorizeSetupAsync(
            request.SetupSecret,
            request.TenantId,
            request.Audit,
            context,
            cancellationToken))
        {
            return Result.Failure<Guid>(AshlarFailureCodes.InvalidSecret);
        }

        return await CompleteFirstAdminBootstrapAsync(request, email, normalizedEmail, context, cancellationToken);
    }

    private async Task<Result<Guid>> CompleteFirstAdminBootstrapAsync(BootstrapFirstAdminRequest request, string email, string normalizedEmail, AuthenticationContext? context, CancellationToken cancellationToken)
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
            return Result.Failure<Guid>(AshlarFailureCodes.AlreadyInitialized);
        }

        var now = _auditContext.TimeProvider.GetUtcNow();
        var grants = _options.Value.Grants;
        var grantService = _grantService;
        if (grants.Count > 0 && grantService is null)
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

            return Result.Failure<Guid>(AshlarFailureCodes.InvalidConfiguration);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var createdUser = await CreateOrActivateFirstAdminUserAsync(normalizedEmail, email, request.UserName, request.TenantId, now, cancellationToken);
        var userId = createdUser.UserId;

        if (grantService is not null)
        {
            foreach (var template in grants)
            {
                var grantResult = await grantService.CreateGrantAsync(new CreateAuthorizationGrantRequest(
                    UserId: userId,
                    TenantId: template.TenantId,
                    ScopeType: template.ScopeType,
                    ScopeId: template.ScopeId,
                    Role: template.Role,
                    Permission: template.Permission,
                    Audit: new AuditContext(ActorUserId: context?.UserId, IpAddress: context?.IpAddress, UserAgent: context?.UserAgent, CorrelationId: context?.CorrelationId)
                ), cancellationToken);

                if (!grantResult.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    await _securityEvents.RecordAsync(new SecurityEventDescriptor
                    {
                        EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                        Outcome = SecurityEventOutcomes.Failure,
                        FailureReason = grantResult.FailureCode?.Value ?? AshlarFailureCodes.GrantCreationFailed.Value,
                        UserId = userId,
                        TenantId = request.TenantId,
                        Audit = request.Audit,
                        Context = context
                    }, cancellationToken);
                    return Result.Failure<Guid>(grantResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.GrantCreationFailed));
                }
            }
        }

        var initialized = await _stateRepository.MarkAsInitializedAsync(userId, now, cancellationToken);
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
            return Result.Failure<Guid>(AshlarFailureCodes.AlreadyInitialized);
        }

        transaction.OnCommitted(async ct =>
        {
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
                }, ct);
            }

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = request.TenantId,
                Audit = request.Audit,
                Context = context
            }, ct);

            var notifiedUser = await _userRepository.GetUserByIdAsync(userId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.BootstrapCompleted, notifiedUser, now, context: context, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(userId);
    }

    private async Task<bool> CheckRateLimitAsync(Guid? tenantId, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        if (_rateLimitChecker is null)
        {
            return true;
        }

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

    private static IAuthorizationGrantService? ValidateGrantService(IAuthorizationGrantService? grantService, BootstrapOptions options)
    {
        if (options.Grants.Count > 0 && grantService is null)
        {
            throw new InvalidOperationException("Bootstrap grants require IAuthorizationGrantService. Register Ashlar authorization services or remove BootstrapOptions.Grants.");
        }

        return grantService;
    }

    private async Task<BootstrapUser> CreateOrActivateFirstAdminUserAsync(
        string normalizedEmail,
        string email,
        string? requestedUserName,
        Guid? tenantId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetUserByEmailAsync(normalizedEmail, tenantId, cancellationToken);
        if (user == null)
        {
            var userId = Guid.NewGuid();
            await _userRepository.CreateUserAsync(new AshlarUser
            {
                Id = userId,
                Email = email,
                Name = requestedUserName,
                IsActive = true,
                EmailVerifiedAt = now,
                TenantId = tenantId
            }, cancellationToken);
            return new BootstrapUser(userId, IsNewUser: true);
        }

        if (!user.IsActive || !user.EmailVerifiedAt.HasValue)
        {
            await _userRepository.UpdateUserAsync(new AshlarUser
            {
                Id = user.Id,
                Email = user.Email,
                Name = requestedUserName ?? user.Name,
                IsActive = true,
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
        var options = _options.Value;
        var failureReason = GetSetupAuthorizationFailureReason(options, setupSecret);
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

    private string? GetSetupAuthorizationFailureReason(BootstrapOptions options, string? setupSecret)
    {
        if (string.IsNullOrWhiteSpace(options.SetupSecret)
            || !SecureTokenHashing.TryHashToken(_tokenContext.Hasher, options.SetupSecret, out var configuredHash))
        {
            return SecurityEventFailureReasons.BootstrapSetupAuthorizationMissing;
        }

        if (!SecureTokenHashing.TryHashToken(_tokenContext.Hasher, setupSecret ?? string.Empty, out var suppliedHash))
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
}
