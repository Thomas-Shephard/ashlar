using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Issues, accepts, and revokes invitations for tenant-aware account onboarding.
/// </summary>
/// <param name="dependencies">Storage, token, messaging, audit, and rate-limit dependencies.</param>
/// <param name="options">Invitation lifetime, delivery, and throttling options.</param>
internal sealed class InvitationService(
    InvitationDependencies dependencies,
    IOptions<InvitationOptions>? options = null) : IInvitationService
{
    private const string InvitationIdProperty = "invitation_id";

    private readonly InvitationDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly IOptions<InvitationOptions> _options = options ?? Options.Create(new InvitationOptions());
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);
    private readonly AuthenticationRateLimitChecker _rateLimitChecker = new(dependencies.RateLimiter);

    /// <summary>
    /// Creates an invitation and sends the acceptance message.
    /// </summary>
    /// <param name="request">Invitation recipient, tenant, and role metadata.</param>
    /// <param name="callbackBaseUri">Validated base URI used to build the acceptance callback.</param>
    /// <param name="context">Authentication context used for audit and rate limiting.</param>
    /// <param name="cancellationToken">A token that can cancel invitation creation.</param>
    /// <returns>A result indicating whether the invitation was created and queued for delivery.</returns>
    public async Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(callbackBaseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);

        _dependencies.UriValidator.ValidateOrThrow(callbackBaseUri);

        var email = IdentityNormalization.SanitizeEmailForDelivery(request.Email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
        var invitationOptions = _options.Value;

        var emailBucket = AuthenticationRateLimitDimensions.Email(normalizedEmail);
        var rateLimit = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck("invitation-create", AuthenticationRateLimitDimensions.DimensionName(emailBucket), emailBucket, invitationOptions.CreationRateLimit)
        {
            Email = normalizedEmail,
            TenantId = request.TenantId,
            Context = context
        }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.RateLimited.Value,
                TenantId = request.TenantId,
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["operation"] = "create" }, normalizedEmail),
                Context = context
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.RateLimited);
        }

        var existingUser = await _dependencies.UserRepository.GetUserByEmailAsync(email, request.TenantId, cancellationToken);
        if (existingUser?.CanSignIn() == true)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationCreated,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.UserExists.Value,
                TenantId = request.TenantId,
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["operation"] = "create" }, normalizedEmail),
                Context = context
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserExists);
        }

        var token = _dependencies.TokenGenerator.GenerateToken();
        var tokenHash = _dependencies.TokenHasher.HashToken(token);
        var now = _dependencies.TimeProvider.GetUtcNow();

        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TenantId = request.TenantId,
            TokenHash = tokenHash,
            CreatedAt = now,
            UpdatedAt = now,
            ExpiresAt = now.Add(request.Expiry ?? invitationOptions.DefaultExpiry),
            Metadata = request.Metadata,
            Version = Guid.NewGuid().ToString()
        };

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        await _dependencies.InvitationRepository.RevokeInvitationsByEmailAsync(email, request.TenantId, cancellationToken);
        await _dependencies.InvitationRepository.CreateInvitationAsync(invitation, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(callbackBaseUri, invitationOptions.TokenParameterName, token);
        var message = IdentityUrlHelper.FormatEmailBody(invitationOptions.EmailTextTemplate, callbackUrl);
        var emailMessage = new EmailMessage(
            email,
            invitationOptions.EmailSubject,
            message,
            options: new EmailMessageOptions { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret });
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_dependencies.EmailSender, transaction, emailMessage, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationCreated,
            Outcome = SecurityEventOutcomes.Success,
            TenantId = request.TenantId,
            Properties = AddEmailIfEnabled(new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() }, normalizedEmail),
            Context = context
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    /// <summary>
    /// Accepts an invitation by raw token and creates or attaches the user.
    /// </summary>
    /// <param name="request">Raw invitation token and acceptance details. Do not log or persist the token.</param>
    /// <param name="context">Authentication context used for audit and rate limiting.</param>
    /// <param name="cancellationToken">A token that can cancel invitation acceptance.</param>
    /// <returns>The accepted or created user identifier, or a failure status.</returns>
    public async Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!await CheckInvitationRateLimitAsync("accept", _options.Value.AcceptanceRateLimit, context, cancellationToken))
        {
            return Result.Failure<Guid>(AshlarFailureCodes.RateLimited);
        }

        var (availableInvitation, auditTenantId, now) = await ResolveAvailableInvitationAsync(request.Token, context, cancellationToken);

        if (availableInvitation == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.InvalidInvitation.Value,
                TenantId = auditTenantId,
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.InvalidInvitation);
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        availableInvitation.AcceptedAt = now;
        availableInvitation.UpdatedAt = now;
        var updated = await _dependencies.InvitationRepository.UpdateInvitationAsync(availableInvitation, availableInvitation.Version, cancellationToken);

        if (!updated)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.ConcurrencyConflict.Value,
                TenantId = availableInvitation.TenantId,
                Properties = new Dictionary<string, string> { [InvitationIdProperty] = availableInvitation.Id.ToString() },
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.ConcurrencyConflict);
        }

        var acceptedUser = await AcceptInvitationUserAsync(availableInvitation, request.UserName, now, cancellationToken);

        if (acceptedUser.IsNewUser)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.UserCreated,
                Outcome = SecurityEventOutcomes.Success,
                UserId = acceptedUser.UserId,
                TenantId = availableInvitation.TenantId,
                Context = context
            }, cancellationToken);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationAccepted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = acceptedUser.UserId,
            TenantId = availableInvitation.TenantId,
            Properties = new Dictionary<string, string> { [InvitationIdProperty] = availableInvitation.Id.ToString() },
            Context = context
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            var notifiedUser = await _dependencies.UserRepository.GetUserByIdAsync(acceptedUser.UserId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.InvitationAccepted, notifiedUser, now, context: context, metadata: new Dictionary<string, string> { [InvitationIdProperty] = availableInvitation.Id.ToString() }, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(acceptedUser.UserId);
    }

    /// <inheritdoc />
    public async Task<Result<InvitationAcceptancePreview>> GetInvitationAcceptancePreviewAsync(string? token, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        if (!await CheckInvitationRateLimitAsync("preview", _options.Value.PreviewRateLimit, context, cancellationToken))
        {
            return Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.RateLimited);
        }

        var (availableInvitation, auditTenantId, _) = await ResolveAvailableInvitationAsync(token, context, cancellationToken);

        if (availableInvitation == null)
        {
            var descriptor = new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationPreviewed,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.InvalidInvitation.Value,
                TenantId = auditTenantId,
                Properties = new Dictionary<string, string> { ["operation"] = "preview" },
                Context = context
            };

            await _securityEvents.RecordAsync(descriptor, cancellationToken);
            return Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation);
        }

        return Result.Success(new InvitationAcceptancePreview(availableInvitation.DisplayEmail, availableInvitation.TenantId));
    }

    private async Task<(UserInvitation? AvailableInvitation, Guid? AuditTenantId, DateTimeOffset Now)> ResolveAvailableInvitationAsync(
        string? token,
        AuthenticationContext? context,
        CancellationToken cancellationToken)
    {
        if (!SecureTokenHashing.TryHashToken(_dependencies.TokenHasher, token, out var tokenHash))
        {
            var failedAt = _dependencies.TimeProvider.GetUtcNow();
            return (null, context?.TenantId, failedAt);
        }

        var invitation = await _dependencies.InvitationRepository.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);
        var now = _dependencies.TimeProvider.GetUtcNow();
        var contextTenantId = context?.TenantId;
        var availableInvitation = invitation is { } candidate && candidate.IsAvailable(now)
            ? candidate
            : null;
        var tenantMismatch = availableInvitation != null && HasTenantContextMismatch(contextTenantId, availableInvitation);
        var auditTenantId = tenantMismatch
            ? contextTenantId
            : invitation?.TenantId ?? contextTenantId;

        return (tenantMismatch ? null : availableInvitation, auditTenantId, now);
    }

    private static bool HasTenantContextMismatch(Guid? contextTenantId, UserInvitation invitation)
    {
        return contextTenantId is Guid tenantId && invitation.TenantId != tenantId;
    }

    private async Task<bool> CheckInvitationRateLimitAsync(string operation, RateLimitRule rule, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        var sourceBucket = AuthenticationRateLimitDimensions.Source(context);
        var rateLimit = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck($"invitation-{operation}", AuthenticationRateLimitDimensions.DimensionName(sourceBucket), sourceBucket, rule)
        {
            Context = context
        }, cancellationToken);

        if (rateLimit.IsAllowed)
        {
            return true;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationRateLimited,
            Outcome = SecurityEventOutcomes.Failure,
            FailureReason = AshlarFailureCodes.RateLimited.Value,
            TenantId = context?.TenantId,
            Properties = new Dictionary<string, string> { ["operation"] = operation },
            Context = context
        }, cancellationToken);
        return false;
    }

    private async Task<AcceptedInvitationUser> AcceptInvitationUserAsync(UserInvitation invitation, string? requestedUserName, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var user = await _dependencies.UserRepository.GetUserByEmailAsync(invitation.DisplayEmail, invitation.TenantId, cancellationToken);

        if (user == null)
        {
            var userId = Guid.NewGuid();
            var newUser = new AshlarUser
            {
                Id = userId,
                DisplayEmail = invitation.DisplayEmail,
                Name = requestedUserName,
                AccountState = UserAccountState.Active,
                EmailVerifiedAt = _options.Value.VerifyEmailOnAcceptance ? now : null,
                TenantId = invitation.TenantId
            };
            await _dependencies.UserRepository.CreateUserAsync(newUser, cancellationToken);
            return new AcceptedInvitationUser(userId, IsNewUser: true);
        }

        if (!user.CanSignIn() || (!user.EmailVerifiedAt.HasValue && _options.Value.VerifyEmailOnAcceptance))
        {
            var updatedUser = new AshlarUser
            {
                Id = user.Id,
                DisplayEmail = user.DisplayEmail,
                Name = requestedUserName ?? user.Name,
                AccountState = UserAccountState.Active,
                EmailVerifiedAt = _options.Value.VerifyEmailOnAcceptance ? (user.EmailVerifiedAt ?? now) : user.EmailVerifiedAt,
                TenantId = invitation.TenantId
            };
            await _dependencies.UserRepository.UpdateUserAsync(updatedUser, cancellationToken);
        }

        return new AcceptedInvitationUser(user.Id, IsNewUser: false);
    }

    /// <summary>
    /// Revokes outstanding invitations for an email address.
    /// </summary>
    /// <param name="email">Recipient email address whose invitations should be revoked.</param>
    /// <param name="tenantId">Tenant scope to revoke within, or <see langword="null" /> for global invitations.</param>
    /// <param name="audit">Actor and request metadata to include in security events.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>A result indicating whether revocation completed.</returns>
    public async Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, AuditContext? audit = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var sanitizedEmail = IdentityNormalization.SanitizeEmailForDelivery(email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(sanitizedEmail);
        var revokedCount = await _dependencies.InvitationRepository.RevokeInvitationsByEmailAsync(sanitizedEmail, tenantId, cancellationToken);

        if (revokedCount > 0)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationRevoked,
                Outcome = SecurityEventOutcomes.Success,
                TenantId = tenantId,
                Audit = audit,
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["count"] = revokedCount.ToString(CultureInfo.InvariantCulture) }, normalizedEmail)
            }, cancellationToken);
        }

        return Result.Success();
    }

    private Dictionary<string, string> AddEmailIfEnabled(Dictionary<string, string> properties, string email)
    {
        if (_options.Value.StoreEmailInAudit)
        {
            properties["email"] = email;
        }

        return properties;
    }

    private sealed record AcceptedInvitationUser(Guid UserId, bool IsNewUser);
}
