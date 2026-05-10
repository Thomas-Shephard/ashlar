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
    private readonly InvitationDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly IOptions<InvitationOptions> _options = options ?? Options.Create(new InvitationOptions());
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);

    public async Task CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(callbackBaseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);

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
                FailureReason = "rate_limited",
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["operation"] = "create" }, normalizedEmail),
                Context = context
            }, cancellationToken);
            throw new InvalidOperationException("Invitation creation is currently rate-limited for this email address.");
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

        var callbackUrl = ConstructCallbackUrl(callbackBaseUri, token);

        transaction.OnCommitted(async ct =>
        {
            await _dependencies.EmailSender.SendAsync(new EmailMessage(email, invitationOptions.EmailSubject, string.Format(CultureInfo.InvariantCulture, invitationOptions.EmailTextTemplate, callbackUrl)), ct);
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationCreated,
                Outcome = SecurityEventOutcomes.Success,
                Properties = AddEmailIfEnabled(new Dictionary<string, string> { ["invitation_id"] = invitation.Id.ToString() }, normalizedEmail),
                Context = context
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<InvitationAcceptanceResult> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
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
                FailureReason = "rate_limited",
                Properties = new Dictionary<string, string> { ["operation"] = "accept" },
                Context = context
            }, cancellationToken);
            return InvitationAcceptanceResult.Failure("rate_limited");
        }

        var invitation = await _dependencies.InvitationRepository.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);
        var now = _dependencies.TimeProvider.GetUtcNow();

        if (invitation == null || !invitation.IsAvailable(now))
        {
            return InvitationAcceptanceResult.Failure("invalid_invitation");
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        invitation.AcceptedAt = now;
        invitation.UpdatedAt = now;
        var updated = await _dependencies.InvitationRepository.UpdateInvitationAsync(invitation, invitation.Version, cancellationToken);

        if (!updated)
        {
            return InvitationAcceptanceResult.Failure("concurrency_conflict");
        }

        var user = await _dependencies.IdentityRepository.GetUserByEmailAsync(invitation.Email, invitation.TenantId, cancellationToken);
        Guid userId;
        var isNewUser = false;

        if (user == null)
        {
            userId = Guid.NewGuid();
            var newUser = new AshlarUser
            {
                Id = userId,
                Email = invitation.Email,
                Name = request.UserName,
                IsActive = true,
                TenantId = invitation.TenantId
            };
            await _dependencies.IdentityRepository.CreateUserAsync(newUser, cancellationToken);
            isNewUser = true;
        }
        else if (!user.IsActive)
        {
            userId = user.Id;
            var updatedUser = new AshlarUser
            {
                Id = user.Id,
                Email = user.Email,
                Name = request.UserName ?? user.Name,
                IsActive = true,
                TenantId = invitation.TenantId
            };
            await _dependencies.IdentityRepository.UpdateUserAsync(updatedUser, cancellationToken);
        }
        else
        {
            userId = user.Id;
        }

        transaction.OnCommitted(async ct =>
        {
            if (isNewUser)
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.UserCreated,
                    Outcome = SecurityEventOutcomes.Success,
                    UserId = userId,
                    Context = context
                }, ct);
            }

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationAccepted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                Properties = new Dictionary<string, string> { ["invitation_id"] = invitation.Id.ToString() },
                Context = context
            }, ct);

            var notifiedUser = await _dependencies.IdentityRepository.GetUserByIdAsync(userId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.InvitationAccepted, notifiedUser, now, context: context, metadata: new Dictionary<string, string> { ["invitation_id"] = invitation.Id.ToString() }, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        return InvitationAcceptanceResult.Success(userId);
    }

    public async Task RevokeInvitationsAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
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
    }

    private Dictionary<string, string> AddEmailIfEnabled(Dictionary<string, string> properties, string email)
    {
        if (_options.Value.StoreEmailInAudit)
        {
            properties["email"] = email;
        }

        return properties;
    }

    private static string ConstructCallbackUrl(Uri baseUri, string token)
    {
        var builder = new UriBuilder(baseUri);
        var query = System.Web.HttpUtility.ParseQueryString(builder.Query);
        query["t"] = token;
        builder.Query = query.ToString();
        return builder.Uri.AbsoluteUri;
    }
}
