using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class EmailChangeService(
    EmailChangeDependencies dependencies,
    IOptions<EmailChangeOptions>? options = null)
    : IEmailChangeService
{
    private const string RequestPurpose = "email-change-request";
    private const string VerifyPurpose = "email-change-verify";
    private const string CredentialPurpose = "email-change";
    private const string ProviderName = "email-change";
    private readonly EmailChangeDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly SecurityEventEmitter _securityEvents = new(dependencies.SecurityEventSink, dependencies.TimeProvider);
    private readonly IOptions<EmailChangeOptions> _options = options ?? Options.Create(new EmailChangeOptions());
    private readonly SecurityNotificationEmitter _notifications = new(dependencies.NotificationService);

    public async Task<EmailChangeResult> RequestChangeAsync(RequestEmailChangeRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_dependencies.UriValidator.IsValid(request.CallbackBaseUri))
        {
            return EmailChangeResult.Failure($"The URI '{request.CallbackBaseUri}' is not allowed.");
        }

        var user = await _dependencies.IdentityContext.Repository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user is not { IsActive: true })
        {
            return EmailChangeResult.Failure("User not found or inactive.");
        }

        var newEmail = IdentityNormalization.SanitizeEmailForDelivery(request.NewEmail);
        var normalizedNewEmail = IdentityNormalization.NormalizeEmail(newEmail);
        if (normalizedNewEmail == IdentityNormalization.NormalizeEmail(user.Email))
        {
            return EmailChangeResult.Failure("New email must be different from the current email.");
        }

        var rateLimit = await _dependencies.RateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"{RequestPurpose}:{user.Id}",
            Purpose = RequestPurpose,
            UserId = user.Id.ToString()
        }, new RateLimitRule { PermitLimit = 3, Window = TimeSpan.FromHours(1) }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = user.Id,
                FailureReason = "rate_limited"
            }, cancellationToken);
            return EmailChangeResult.Failure("Too many requests.");
        }

        var existingUser = await _dependencies.IdentityContext.Repository.GetUserByEmailAsync(normalizedNewEmail, (user as ITenantUser)?.TenantId, cancellationToken);
        if (existingUser != null) return await SuppressEmailChangeRequestAsync(newEmail, user, cancellationToken);

        var token = _dependencies.TokenContext.Generator.GenerateToken();
        var tokenHash = _dependencies.TokenContext.Hasher.HashToken(token);
        var now = _dependencies.TimeProvider.GetUtcNow();

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ProviderType = ProviderType.Internal,
            ProviderName = ProviderName,
            ProviderKey = tokenHash,
            Version = Guid.NewGuid().ToString("N"),
            CredentialValue = _dependencies.SecretProtector.Protect(newEmail),
            CreatedAt = now,
            ExpiresAt = now.Add(_options.Value.Expiration),
            Status = CredentialStatus.Active,
            Purpose = CredentialPurpose
        };

        await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        await _dependencies.IdentityContext.Repository.RevokeCredentialsAsync(user.Id, ProviderType.Internal, ProviderName, cancellationToken);
        await _dependencies.IdentityContext.Repository.CreateOrReplaceCredentialAsync(credential, cancellationToken);

        var callbackUrl = IdentityUrlHelper.ConstructCallbackUrl(request.CallbackBaseUri, _options.Value.TokenParameterName, token, user.Id, _options.Value.UserIdParameterName);
        var message = IdentityUrlHelper.FormatEmailBody(_options.Value.EmailTextTemplate, callbackUrl, "Confirmation token", token);

        transaction.OnCommitted(async ct =>
        {
            await _dependencies.EmailSender.SendAsync(new EmailMessage(
                newEmail,
                _options.Value.Subject,
                message,
                options: new EmailMessageOptions { From = _options.Value.FromAddress }), ct);

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeRequested,
                Outcome = SecurityEventOutcomes.Success,
                UserId = user.Id,
                Properties = new Dictionary<string, string> { ["new_email"] = newEmail }
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return EmailChangeResult.Success();
    }

    private async Task<EmailChangeResult> SuppressEmailChangeRequestAsync(string newEmail, IUser user, CancellationToken cancellationToken)
    {
        await using var suppressionTransaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);
        suppressionTransaction.OnCommitted(async ct =>
        {
            await _dependencies.EmailSender.SendAsync(new EmailMessage(
                newEmail,
                _options.Value.Subject,
                "An attempt was made to change another account's email address to this one. No changes were made, and no further action is required.",
                options: new EmailMessageOptions { From = _options.Value.FromAddress }), ct);

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeRequestSuppressed,
                Outcome = SecurityEventOutcomes.Success,
                UserId = user.Id,
                FailureReason = "email_already_in_use"
            }, ct);
        });

        await suppressionTransaction.CommitAsync(cancellationToken);
        return EmailChangeResult.Success();
    }

    public async Task<EmailChangeResult> ConfirmChangeAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Token);

        var rateLimit = await _dependencies.RateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"{VerifyPurpose}:{request.UserId}",
            Purpose = VerifyPurpose,
            UserId = request.UserId.ToString()
        }, new RateLimitRule { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChangeVerificationRateLimited,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                FailureReason = "rate_limited"
            }, cancellationToken);
            return EmailChangeResult.Failure("Too many attempts.");
        }

        var tokenHash = _dependencies.TokenContext.Hasher.HashToken(request.Token);
        var credential = await _dependencies.IdentityContext.Repository.GetCredentialForUserAsync(request.UserId, ProviderType.Internal, ProviderName, tokenHash, cancellationToken);

        var now = _dependencies.TimeProvider.GetUtcNow();
        if (credential == null || !credential.IsAvailable(now) || string.IsNullOrWhiteSpace(credential.CredentialValue))
        {
            return EmailChangeResult.Failure("Invalid or expired token.");
        }

        string newEmail;
        try
        {
            newEmail = IdentityNormalization.SanitizeEmailForDelivery(_dependencies.SecretProtector.Unprotect(credential.CredentialValue));
        }
        catch (Exception)
        {
            return EmailChangeResult.Failure("Invalid token data.");
        }

        var normalizedNewEmail = IdentityNormalization.NormalizeEmail(newEmail);

        await using var transaction = await _dependencies.IdentityContext.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _dependencies.IdentityContext.Repository.GetUserByIdAsync(request.UserId, cancellationToken);
        if (user is not { IsActive: true })
        {
            return EmailChangeResult.Failure("Invalid or expired token.");
        }

        var consumed = await _dependencies.IdentityContext.Repository.ConsumeCredentialAsync(credential.Id, credential.Version, cancellationToken);
        if (!consumed)
        {
            return EmailChangeResult.Failure("Invalid or expired token.");
        }

        var existingUser = await _dependencies.IdentityContext.Repository.GetUserByEmailAsync(normalizedNewEmail, (user as ITenantUser)?.TenantId, cancellationToken);
        if (existingUser != null)
        {
            transaction.OnCommitted(async ct =>
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.EmailChangeFailed,
                    Outcome = SecurityEventOutcomes.Failure,
                    UserId = user.Id,
                    FailureReason = "email_already_in_use"
                }, ct);
            });
            await transaction.CommitAsync(cancellationToken);
            return EmailChangeResult.Failure("New email is already in use.");
        }

        var oldEmail = user.Email;
        // Update user
        var updatedUser = new UpdatedUserWrapper(user, newEmail, now);

        await _dependencies.IdentityContext.Repository.UpdateUserAsync(updatedUser, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            if (_options.Value.RevokeSessions)
            {
                await _dependencies.SessionRepository.RevokeSessionsForUserAsync(user.Id, now, "Email changed", ct);
            }

            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.EmailChanged,
                Outcome = SecurityEventOutcomes.Success,
                UserId = user.Id,
                Properties = new Dictionary<string, string>
                {
                    ["old_email"] = oldEmail,
                    ["new_email"] = newEmail
                }
            }, ct);

            var notificationMetadata = new Dictionary<string, string>
            {
                ["old_email"] = oldEmail,
                ["new_email"] = newEmail
            };

            await _notifications.NotifyAsync(SecurityNotificationType.EmailChanged, oldEmail, now, metadata: notificationMetadata, cancellationToken: ct);
            await _notifications.NotifyAsync(SecurityNotificationType.EmailChanged, updatedUser, now, metadata: notificationMetadata, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return EmailChangeResult.Success();
    }

    private sealed class UpdatedUserWrapper(IUser original, string newEmail, DateTimeOffset? emailVerifiedAt) : ITenantUser, IHasAuditMetadata
    {
        public Guid Id => original.Id;
        public string Email { get; } = newEmail;
        public string? Name => original.Name;
        public bool IsActive => original.IsActive;
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        public DateTimeOffset? EmailVerifiedAt { get; } = emailVerifiedAt;
        public DateTimeOffset CreatedAt => (original as IHasAuditMetadata)?.CreatedAt ?? default;
        public DateTimeOffset? UpdatedAt
        {
            get => (original as IHasAuditMetadata)?.UpdatedAt;
            set
            {
                if (original is IHasAuditMetadata metadata)
                    metadata.UpdatedAt = value;
            }
        }
    }
}
