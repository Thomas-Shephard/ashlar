using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Totp;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

/// <summary>
/// Implements administrator-oriented account security operations.
/// </summary>
/// <param name="identityRepository">The identity repository value.</param>
/// <param name="sessionService">The session service value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
/// <param name="accountSecurityGuard">The account security guard value.</param>
/// <param name="dependencies">The dependencies value.</param>
public sealed class AccountSecurityService : IAccountSecurityService
{
    private const string AdminReason = "admin";
    private readonly IIdentityRepository _identityRepository;
    private readonly IAuthenticationSessionService _sessionService;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IAccountSecurityGuard _accountSecurityGuard;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IUserSecurityEventSummaryRepository? _securityEventSummaryRepository;
    private readonly AuthenticationProviderKey _totpProvider;
    private readonly AuthenticationProviderKey _recoveryCodeProvider;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="identityRepository">The identity repository value.</param>
    /// <param name="sessionService">The session service value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="accountSecurityGuard">The account security guard value.</param>
    /// <param name="dependencies">The dependencies value.</param>
    public AccountSecurityService(
        IIdentityRepository identityRepository,
        IAuthenticationSessionService sessionService,
        IAshlarTransactionProvider transactionProvider,
        IAccountSecurityGuard accountSecurityGuard,
        AccountSecurityServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _identityRepository = identityRepository ?? throw new ArgumentNullException(nameof(identityRepository));
        _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _accountSecurityGuard = accountSecurityGuard ?? throw new ArgumentNullException(nameof(accountSecurityGuard));
        _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider);
        _securityEventSummaryRepository = dependencies.SecurityEventSummaryRepository;
        _totpProvider = dependencies.TotpOptions?.Value.ProviderKey ?? TotpOptions.DefaultProviderKey;
        _recoveryCodeProvider = dependencies.RecoveryCodeOptions?.Value.ProviderKey ?? new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> DisableUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var user = await _identityRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !IsInRequestedTenant(user, request.Tenant))
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserDisabled, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        var changed = user.IsActive;
        if (changed)
        {
            var guardResult = await _accountSecurityGuard.CanDisableUserAsync(user, request, cancellationToken);
            if (!guardResult.Succeeded)
            {
                await RecordFailureAsync(AshlarSecurityEventTypes.UserDisabled, userId, request, guardResult.FailureCode?.Value ?? AshlarFailureCodes.ValidationError.Value, cancellationToken);
                return Result.Failure<AccountSecurityOperationResult>(guardResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.ValidationError));
            }

            await _identityRepository.UpdateUserAsync(CloneUser(user, isActive: false), cancellationToken);
        }

        var revoked = await _sessionService.RevokeSessionsForUserAsync(userId, request.Reason ?? AdminReason, request.Tenant, request.Audit, cancellationToken);
        var result = new AccountSecurityOperationResult(userId, changed, SessionsRevoked: revoked);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserDisabled, result, request, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> ReactivateUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var user = await _identityRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !IsInRequestedTenant(user, request.Tenant))
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserReactivated, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        var changed = !user.IsActive;
        if (changed)
        {
            await _identityRepository.UpdateUserAsync(CloneUser(user, isActive: true), cancellationToken);
        }

        var result = new AccountSecurityOperationResult(userId, changed);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserReactivated, result, request, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);
        var user = await _identityRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !IsInRequestedTenant(user, request.Tenant))
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.SessionsRevokedForUser, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        var revoked = await _sessionService.RevokeSessionsForUserAsync(userId, request.Reason ?? AdminReason, request.Tenant, request.Audit, cancellationToken);
        return Result.Success(new AccountSecurityOperationResult(userId, SessionsRevoked: revoked));
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        ValidateProvider(provider);
        request = RequireAudit(request);

        var user = await _identityRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !IsInRequestedTenant(user, request.Tenant))
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserCredentialsRevoked, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken, provider);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var revoked = await _identityRepository.RevokeCredentialsAsync(userId, provider.Type, provider.Name, cancellationToken);
        var result = new AccountSecurityOperationResult(userId, CredentialsRevoked: revoked);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserCredentialsRevoked, result, request, ct, provider));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);

        var user = await _identityRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !IsInRequestedTenant(user, request.Tenant))
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserMfaReset, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var revoked = await _identityRepository.RevokeCredentialsAsync(userId, _totpProvider.Type, _totpProvider.Name, cancellationToken);
        revoked += await _identityRepository.RevokeCredentialsAsync(userId, _recoveryCodeProvider.Type, _recoveryCodeProvider.Name, cancellationToken);
        var result = new AccountSecurityOperationResult(userId, CredentialsRevoked: revoked);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserMfaReset, result, request, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<UserSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, UserSecurityPostureRequest? request = null, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request ??= new UserSecurityPostureRequest();

        var user = await _identityRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !IsInRequestedTenant(user, request.Tenant))
        {
            return Result.Failure<UserSecurityPosture>(AshlarFailureCodes.UserNotFound);
        }

        var credentials = await _identityRepository.ListCredentialsForUserAsync(userId, activeOnly: true, cancellationToken);
        var sessions = await _sessionService.ListSessionsForUserAsync(userId, new ListAuthenticationSessionsRequest { ActiveOnly = true }, cancellationToken);
        int? eventCount = null;
        if (_securityEventSummaryRepository != null && request.RecentSecurityEventWindow is { } window)
        {
            eventCount = await _securityEventSummaryRepository.CountSecurityEventsForUserAsync(userId, _timeProvider.GetUtcNow().Subtract(window), cancellationToken);
        }

        var providerKeys = credentials
            .Select(c => new AuthenticationProviderKey(c.ProviderType, c.ProviderName))
            .Distinct()
            .OrderBy(k => k.Type.Value, StringComparer.Ordinal)
            .ThenBy(k => k.Name, StringComparer.Ordinal)
            .ToList()
            .AsReadOnly();

        var posture = new UserSecurityPosture(
            userId,
            user.IsActive,
            user.EmailVerifiedAt.HasValue,
            providerKeys,
            providerKeys.Any(IsMfaProvider),
            sessions.Count,
            eventCount);

        return Result.Success(posture);
    }

    private static AccountSecurityOperationRequest RequireAudit(AccountSecurityOperationRequest? request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request), "Admin account security operations require audit metadata.");
        }

        return request;
    }

    private static void ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }
    }

    private static void ValidateProvider(AuthenticationProviderKey provider)
    {
        if (provider.Type == default || string.IsNullOrWhiteSpace(provider.Name))
        {
            throw new ArgumentException("Provider key must be fully initialized.", nameof(provider));
        }
    }

    private static bool IsInRequestedTenant(IUser user, TenantContext? tenant)
    {
        if (tenant == null)
        {
            return true;
        }

        if (user is not ITenantUser tenantUser)
        {
            return false;
        }

        return tenantUser.TenantId == tenant.TenantId;
    }

    private bool IsMfaProvider(AuthenticationProviderKey provider)
    {
        return provider.Type == ProviderType.Mfa
               || provider.Type == ProviderType.RecoveryCode
               || provider == _totpProvider
               || provider == _recoveryCodeProvider;
    }

    private static AshlarUser CloneUser(IUser user, bool isActive)
    {
        return new AshlarUser
        {
            Id = user.Id,
            Email = user.Email,
            Name = user.Name,
            IsActive = isActive,
            TenantId = (user as ITenantUser)?.TenantId,
            EmailVerifiedAt = user.EmailVerifiedAt
        };
    }

    private Task RecordFailureAsync(string eventType, Guid userId, AccountSecurityOperationRequest request, string failureReason, CancellationToken cancellationToken, AuthenticationProviderKey? provider = null)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = request.Tenant?.TenantId,
            Audit = request.Audit,
            Provider = provider,
            FailureReason = failureReason
        }, cancellationToken);
    }

    private Task RecordSuccessAsync(string eventType, AccountSecurityOperationResult result, AccountSecurityOperationRequest request, CancellationToken cancellationToken, AuthenticationProviderKey? provider = null)
    {
        var properties = new Dictionary<string, string>
        {
            ["user_changed"] = result.UserChanged ? "true" : "false",
            ["sessions_revoked"] = result.SessionsRevoked.ToString(CultureInfo.InvariantCulture),
            ["credentials_revoked"] = result.CredentialsRevoked.ToString(CultureInfo.InvariantCulture)
        };
        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Success,
            UserId = result.UserId,
            TenantId = request.Tenant?.TenantId,
            Audit = request.Audit,
            Provider = provider,
            Properties = properties
        }, cancellationToken);
    }
}

/// <summary>
/// Dependencies for <see cref="AccountSecurityService"/>.
/// </summary>
/// <param name="TimeProvider">The time provider value.</param>
/// <param name="SecurityEventSink">The security event sink value.</param>
/// <param name="SecurityEventSummaryRepository">The security event summary repository value.</param>
/// <param name="TotpOptions">The TOTP options value.</param>
/// <param name="RecoveryCodeOptions">The recovery code options value.</param>
public sealed record AccountSecurityServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    IUserSecurityEventSummaryRepository? SecurityEventSummaryRepository = null,
    IOptions<TotpOptions>? TotpOptions = null,
    IOptions<RecoveryCodeOptions>? RecoveryCodeOptions = null);
