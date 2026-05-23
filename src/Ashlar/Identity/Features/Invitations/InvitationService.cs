using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Provides invitation service behavior.
/// </summary>
/// <param name="dependencies">The dependencies value.</param>
/// <param name="options">The options value.</param>
internal sealed class InvitationService(
    InvitationDependencies dependencies,
    IOptions<InvitationOptions>? options = null) : IInvitationService
{
    private const string InvitationIdProperty = "invitation_id";

    private readonly InvitationDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly IOptions<InvitationOptions> _options = options ?? Options.Create(new InvitationOptions());
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);

    /// <summary>
    /// Performs the create invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="callbackBaseUri">The callback base uri value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(callbackBaseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);

        _dependencies.UriValidator.ValidateOrThrow(callbackBaseUri);

        var email = IdentityNormalization.SanitizeEmailForDelivery(request.Email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
        var invitationOptions = _options.Value;

        var rateLimitKey = $"invitation-create:{normalizedEmail}";
        var rateLimit = await _dependencies.RateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = rateLimitKey,
            Purpose = "invitation-create",
            Email = normalizedEmail,
            IpAddress = context?.IpAddress,
            CorrelationId = context?.CorrelationId
        }, invitationOptions.CreationRateLimit, cancellationToken);

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

        var existingUser = await _dependencies.IdentityRepository.GetUserByEmailAsync(normalizedEmail, request.TenantId, cancellationToken);
        if (existingUser is { IsActive: true })
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
            Email = email,
            TenantId = request.TenantId,
            TokenHash = tokenHash,
            CreatedAt = now,
            UpdatedAt = now,
            ExpiresAt = now.Add(request.Expiry ?? invitationOptions.DefaultExpiry),
            Metadata = request.Metadata,
            Version = Guid.NewGuid().ToString()
        };

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        await _dependencies.InvitationRepository.RevokeInvitationsByEmailAsync(normalizedEmail, request.TenantId, cancellationToken);
        await _dependencies.InvitationRepository.CreateInvitationAsync(invitation, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(callbackBaseUri, invitationOptions.TokenParameterName, token);
        var message = IdentityUrlHelper.FormatEmailBody(invitationOptions.EmailTextTemplate, callbackUrl);

        transaction.OnCommitted(async ct =>
        {
            await _dependencies.EmailSender.SendAsync(new EmailMessage(email, invitationOptions.EmailSubject, message), ct);
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationCreated,
                Outcome = SecurityEventOutcomes.Success,
                TenantId = request.TenantId,
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() }, normalizedEmail),
                Context = context
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    /// <summary>
    /// Performs the accept invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Token);

        if (!await CheckInvitationRateLimitAsync("accept", _options.Value.AcceptanceRateLimit, context, cancellationToken))
        {
            return Result.Failure<Guid>(AshlarFailureCodes.RateLimited);
        }

        var tokenHash = _dependencies.TokenHasher.HashToken(request.Token);
        var invitation = await _dependencies.InvitationRepository.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);
        var now = _dependencies.TimeProvider.GetUtcNow();

        if (invitation == null || !invitation.IsAvailable(now))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.InvalidInvitation.Value,
                TenantId = context?.TenantId,
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.InvalidInvitation);
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        invitation.AcceptedAt = now;
        invitation.UpdatedAt = now;
        var updated = await _dependencies.InvitationRepository.UpdateInvitationAsync(invitation, invitation.Version, cancellationToken);

        if (!updated)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.ConcurrencyConflict.Value,
                TenantId = invitation.TenantId,
                Properties = new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() },
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.ConcurrencyConflict);
        }

        var acceptedUser = await AcceptInvitationUserAsync(invitation, request.UserName, now, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            if (acceptedUser.IsNewUser)
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.UserCreated,
                    Outcome = SecurityEventOutcomes.Success,
                    UserId = acceptedUser.UserId,
                    TenantId = invitation.TenantId,
                    Context = context
                }, ct);
            }

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = acceptedUser.UserId,
                TenantId = invitation.TenantId,
                Properties = new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() },
                Context = context
            }, ct);

            var notifiedUser = await _dependencies.IdentityRepository.GetUserByIdAsync(acceptedUser.UserId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.InvitationAccepted, notifiedUser, now, context: context, metadata: new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() }, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(acceptedUser.UserId);
    }

    /// <inheritdoc />
    public async Task<Result<InvitationAcceptancePreview>> GetInvitationAcceptancePreviewAsync(string token, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        if (!await CheckInvitationRateLimitAsync("preview", _options.Value.PreviewRateLimit, context, cancellationToken))
        {
            return Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.RateLimited);
        }

        var tokenHash = _dependencies.TokenHasher.HashToken(token);
        var invitation = await _dependencies.InvitationRepository.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);
        if (invitation == null || !invitation.IsAvailable(_dependencies.TimeProvider.GetUtcNow()))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationPreviewed,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.InvalidInvitation.Value,
                TenantId = invitation?.TenantId ?? context?.TenantId,
                Properties = new Dictionary<string, string> { ["operation"] = "preview" },
                Context = context
            }, cancellationToken);
            return Result.Failure<InvitationAcceptancePreview>(AshlarFailureCodes.InvalidInvitation);
        }

        return Result.Success(new InvitationAcceptancePreview(invitation.Email, invitation.TenantId));
    }

    private async Task<bool> CheckInvitationRateLimitAsync(string operation, RateLimitRule rule, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        var ipAddress = string.IsNullOrWhiteSpace(context?.IpAddress) ? "unknown-ip" : context.IpAddress;
        var rateLimitKey = $"invitation-{operation}:{ipAddress}";
        var rateLimit = await _dependencies.RateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = rateLimitKey,
            Purpose = $"invitation-{operation}",
            IpAddress = ipAddress,
            CorrelationId = context?.CorrelationId
        }, rule, cancellationToken);

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
        var user = await _dependencies.IdentityRepository.GetUserByEmailAsync(invitation.Email, invitation.TenantId, cancellationToken);

        if (user == null)
        {
            var userId = Guid.NewGuid();
            var newUser = new AshlarUser
            {
                Id = userId,
                Email = invitation.Email,
                Name = requestedUserName,
                IsActive = true,
                EmailVerifiedAt = _options.Value.VerifyEmailOnAcceptance ? now : null,
                TenantId = invitation.TenantId
            };
            await _dependencies.IdentityRepository.CreateUserAsync(newUser, cancellationToken);
            return new AcceptedInvitationUser(userId, IsNewUser: true);
        }

        if (!user.IsActive || (!user.EmailVerifiedAt.HasValue && _options.Value.VerifyEmailOnAcceptance))
        {
            var updatedUser = new AshlarUser
            {
                Id = user.Id,
                Email = user.Email,
                Name = requestedUserName ?? user.Name,
                IsActive = true,
                EmailVerifiedAt = _options.Value.VerifyEmailOnAcceptance ? (user.EmailVerifiedAt ?? now) : user.EmailVerifiedAt,
                TenantId = invitation.TenantId
            };
            await _dependencies.IdentityRepository.UpdateUserAsync(updatedUser, cancellationToken);
        }

        return new AcceptedInvitationUser(user.Id, IsNewUser: false);
    }

    /// <summary>
    /// Performs the revoke invitations <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="audit">The audit metadata value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, AuditContext? audit = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var sanitizedEmail = IdentityNormalization.SanitizeEmailForDelivery(email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(sanitizedEmail);
        var revokedCount = await _dependencies.InvitationRepository.RevokeInvitationsByEmailAsync(normalizedEmail, tenantId, cancellationToken);

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
