using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class InvitationService(
    InvitationDependencies dependencies,
    IOptions<InvitationOptions>? options = null) : IInvitationService
{
    private const string InvitationIdProperty = "invitation_id";
    private const string RateLimitedFailureReason = "rate_limited";

    private readonly InvitationDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly IOptions<InvitationOptions> _options = options ?? Options.Create(new InvitationOptions());
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);

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
                FailureReason = RateLimitedFailureReason,
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["operation"] = "create" }, normalizedEmail),
                Context = context
            }, cancellationToken);
            return Result.Failure(RateLimitedFailureReason);
        }

        var existingUser = await _dependencies.IdentityRepository.GetUserByEmailAsync(normalizedEmail, request.TenantId, cancellationToken);
        if (existingUser is { IsActive: true })
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationCreated,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = "user_exists",
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["operation"] = "create" }, normalizedEmail),
                Context = context
            }, cancellationToken);
            return Result.Failure("user_exists");
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
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() }, normalizedEmail),
                Context = context
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    public async Task<Result<Guid>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Token);

        var tokenHash = _dependencies.TokenHasher.HashToken(request.Token);
        var rateLimitKey = $"invitation-accept:{context?.IpAddress ?? "unknown-ip"}";
        var rateLimit = await _dependencies.RateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = rateLimitKey,
            Purpose = "invitation-accept",
            IpAddress = context?.IpAddress,
            CorrelationId = context?.CorrelationId
        }, _options.Value.AcceptanceRateLimit, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = RateLimitedFailureReason,
                Properties = new Dictionary<string, string> { ["operation"] = "accept" },
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(RateLimitedFailureReason);
        }

        var invitation = await _dependencies.InvitationRepository.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);
        var now = _dependencies.TimeProvider.GetUtcNow();

        if (invitation == null || !invitation.IsAvailable(now))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = "invalid_invitation",
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>("invalid_invitation");
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
                FailureReason = "concurrency_conflict",
                Properties = new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() },
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>("concurrency_conflict");
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
                    Context = context
                }, ct);
            }

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = acceptedUser.UserId,
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

    public async Task<Result> RevokeInvitationsAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
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
