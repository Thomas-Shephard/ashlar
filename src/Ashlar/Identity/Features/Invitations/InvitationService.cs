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
    /// <param name="context">Authentication context used for tenant scope, audit, and rate limiting. Tenant-owned invitations require a matching tenant context; a missing tenant is global-only.</param>
    /// <param name="cancellationToken">A token that can cancel invitation acceptance.</param>
    /// <returns>The accepted or created user identifier, or a failure status.</returns>
    public async Task<Result<InvitationAcceptanceResult>> AcceptInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!await CheckInvitationRateLimitAsync("accept", _options.Value.AcceptanceRateLimit, context, cancellationToken))
        {
            return Result.Failure<InvitationAcceptanceResult>(AshlarFailureCodes.RateLimited);
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
            return Result.Failure<InvitationAcceptanceResult>(AshlarFailureCodes.InvalidInvitation);
        }

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var acceptedInvitation = new UserInvitation
        {
            Id = availableInvitation.Id,
            DisplayEmail = availableInvitation.DisplayEmail,
            TenantId = availableInvitation.TenantId,
            TokenHash = availableInvitation.TokenHash,
            CreatedAt = availableInvitation.CreatedAt,
            UpdatedAt = now,
            ExpiresAt = availableInvitation.ExpiresAt,
            AcceptedAt = now,
            RevokedAt = availableInvitation.RevokedAt,
            Metadata = availableInvitation.Metadata,
            Version = availableInvitation.Version
        };
        var updated = await _dependencies.InvitationRepository.UpdateInvitationAsync(acceptedInvitation, availableInvitation.Version, cancellationToken);

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
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure<InvitationAcceptanceResult>(AshlarFailureCodes.ConcurrencyConflict);
        }

        var acceptedUser = await AcceptInvitationUserAsync(acceptedInvitation, request.UserName, now, cancellationToken);

        if (acceptedUser.IsNewUser)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.UserCreated,
                Outcome = SecurityEventOutcomes.Success,
                UserId = acceptedUser.UserId,
                TenantId = acceptedInvitation.TenantId,
                Context = context
            }, cancellationToken);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationAccepted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = acceptedUser.UserId,
            TenantId = acceptedInvitation.TenantId,
            Properties = new Dictionary<string, string> { [InvitationIdProperty] = acceptedInvitation.Id.ToString() },
            Context = context
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            var notifiedUser = await _dependencies.UserRepository.GetUserByIdAsync(acceptedUser.UserId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.InvitationAccepted, notifiedUser, now, context: context, metadata: new Dictionary<string, string> { [InvitationIdProperty] = acceptedInvitation.Id.ToString() }, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        var authenticatedUser = await _dependencies.UserRepository.GetUserByIdAsync(acceptedUser.UserId, cancellationToken)
            ?? throw new InvalidOperationException("Accepted invitation user could not be loaded for session issuance.");
        return Result.Success(new InvitationAcceptanceResult(acceptedUser.UserId, CreateSessionIssuanceResult(authenticatedUser)));
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
        return invitation.TenantId != contextTenantId;
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

    private static MfaAuthenticationResult CreateSessionIssuanceResult(IUser user)
    {
        return new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user)
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.Instance
        };
    }

    /// <inheritdoc />
    public async Task<Result> RevokeInvitationsAsync(RevokeInvitationsRequest request, CancellationToken cancellationToken = default)
    {
        ValidatedRevokeInvitationsRequest validated;
        try
        {
            validated = ValidateRevokeInvitationsRequest(request);
        }
        catch (ArgumentException exception)
        {
            return Result.Failure(AshlarFailureCodes.ValidationError, exception.Message);
        }

        var sanitizedEmail = IdentityNormalization.SanitizeEmailForDelivery(validated.Email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(sanitizedEmail);

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);
        int revokedCount;
        Guid? auditTenantId;
        string tenantScope;
        if (validated.IncludeAllTenants)
        {
            revokedCount = await RevokeInvitationsAcrossAllTenantsAsync(sanitizedEmail, validated.Audit, cancellationToken);
            auditTenantId = null;
            tenantScope = "all";
        }
        else
        {
            var scopedTenant = validated.Tenant;
            revokedCount = await _dependencies.InvitationRepository.RevokeInvitationsByEmailAsync(sanitizedEmail, scopedTenant.TenantId, cancellationToken);
            auditTenantId = scopedTenant.TenantId;
            tenantScope = scopedTenant.TenantId.HasValue ? "tenant" : "global";
        }

        if (revokedCount > 0)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.InvitationRevoked,
                Outcome = SecurityEventOutcomes.Success,
                TenantId = auditTenantId,
                Audit = validated.Audit,
                Properties = AddEmailIfEnabled(new Dictionary<string, string>
                {
                    ["count"] = revokedCount.ToString(CultureInfo.InvariantCulture),
                    ["tenant_scope"] = tenantScope
                }, normalizedEmail)
            }, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    private static ValidatedRevokeInvitationsRequest ValidateRevokeInvitationsRequest(RevokeInvitationsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.Audit == null)
        {
            throw new ArgumentException("Audit metadata is required for invitation revocation.", nameof(request));
        }

        return new ValidatedRevokeInvitationsRequest(request.Email, request.Tenant ?? TenantContext.Global, request.IncludeAllTenants, request.Audit);
    }

    private async Task<int> RevokeInvitationsAcrossAllTenantsAsync(string email, AuditContext audit, CancellationToken cancellationToken)
    {
        var count = 0;
        while (true)
        {
            var pending = await _dependencies.InvitationRepository.SearchInvitationsAsync(new SearchInvitationsRequest
            {
                Email = email,
                Status = InvitationAdministrationStatus.Pending,
                IncludeAllTenants = true,
                Limit = InvitationAdministrationService.MaximumLimit
            }, _dependencies.TimeProvider.GetUtcNow(), cancellationToken);

            if (pending.Count == 0)
            {
                return count;
            }

            foreach (var invitation in pending)
            {
                var result = await _dependencies.InvitationRepository.RevokeInvitationAsync(new RevokeInvitationAdministrationRequest(invitation.Id, IncludeAllTenants: true, Audit: audit), _dependencies.TimeProvider.GetUtcNow(), cancellationToken);
                if (result?.RevocationStatus == InvitationAdministrationRevocationStatus.Revoked)
                {
                    count++;
                }
            }
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

    private sealed record AcceptedInvitationUser(Guid UserId, bool IsNewUser);

    private sealed record ValidatedRevokeInvitationsRequest(
        string Email,
        TenantContext Tenant,
        bool IncludeAllTenants,
        AuditContext Audit);
}
