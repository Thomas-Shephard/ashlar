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
    IOptions<InvitationOptions>? options = null) : IInvitationService, IInvitationMutationExecutor
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
    public async Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri,
        AuthenticationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ValidateCreateInvitation(request, callbackBaseUri);
        if (context.UserId is not { } actorUserId || actorUserId == Guid.Empty)
            throw new ArgumentException("Actor user ID cannot be empty.", nameof(context));
        if (context.CurrentSessionId is not { } currentSessionId || currentSessionId == Guid.Empty)
            throw new ArgumentException("Current session ID cannot be empty.", nameof(context));
        if (context.TenantId != request.TenantId)
            throw new ArgumentException("Authentication context tenant must match the invitation tenant.", nameof(context));

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
                SessionId = context.CurrentSessionId,
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
                SessionId = context.CurrentSessionId,
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
            invitationOptions.EmailSubject, EmailMessageSensitivity.ContainsLiveSecret,
            message);
        await TransactionalEmailDelivery.SendOrRegisterPostCommitAsync(_dependencies.EmailSender, transaction, emailMessage, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationCreated,
            Outcome = SecurityEventOutcomes.Success,
            TenantId = request.TenantId,
            SessionId = context.CurrentSessionId,
            Properties = AddEmailIfEnabled(new Dictionary<string, string> { [InvitationIdProperty] = invitation.Id.ToString() }, normalizedEmail),
            Context = context
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    /// <summary>
    /// Accepts an invitation by raw token, creating a user or accepting for an existing active user.
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

        var existingUser = await _dependencies.UserRepository.GetUserByEmailAsync(availableInvitation.DisplayEmail, availableInvitation.TenantId, cancellationToken);
        if (existingUser != null)
        {
            existingUser = await _dependencies.UserRepository.GetUserByIdAsync(existingUser.Id, cancellationToken);
            if (existingUser is not { AccountState: UserAccountState.Active }
                || !UserTenantOwnership.Matches(existingUser, availableInvitation.TenantId)
                || IdentityNormalization.NormalizeEmail(existingUser.DisplayEmail) != IdentityNormalization.NormalizeEmail(availableInvitation.DisplayEmail))
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.InvitationAccepted,
                    Outcome = SecurityEventOutcomes.Failure,
                    FailureReason = AshlarFailureCodes.InvalidInvitation.Value,
                    TenantId = availableInvitation.TenantId,
                    Context = context
                }, cancellationToken);
                return Result.Failure<InvitationAcceptanceResult>(AshlarFailureCodes.InvalidInvitation);
            }
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

        var acceptedUser = await AcceptInvitationUserAsync(acceptedInvitation, existingUser, request.UserName, now, cancellationToken);

        if (acceptedUser.IsNewUser)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.UserCreated,
                Outcome = SecurityEventOutcomes.Success,
                UserId = acceptedUser.User.Id,
                TenantId = acceptedInvitation.TenantId,
                Context = context
            }, cancellationToken);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationAccepted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = acceptedUser.User.Id,
            TenantId = acceptedInvitation.TenantId,
            Properties = new Dictionary<string, string> { [InvitationIdProperty] = acceptedInvitation.Id.ToString() },
            Context = context
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            var notifiedUser = await _dependencies.UserRepository.GetUserByIdAsync(acceptedUser.User.Id, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.InvitationAccepted, notifiedUser, now, context: context, metadata: new Dictionary<string, string> { [InvitationIdProperty] = acceptedInvitation.Id.ToString() }, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(new InvitationAcceptanceResult(acceptedUser.User.Id, CreateSessionIssuanceResult(acceptedUser.User)));
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

    private async Task<AcceptedInvitationUser> AcceptInvitationUserAsync(UserInvitation invitation, IUser? user, string? requestedUserName, DateTimeOffset now, CancellationToken cancellationToken)
    {
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
            return new AcceptedInvitationUser(newUser, IsNewUser: true);
        }

        if (!user.EmailVerifiedAt.HasValue && _options.Value.VerifyEmailOnAcceptance)
        {
            var updatedUser = new AshlarUser
            {
                Id = user.Id,
                DisplayEmail = user.DisplayEmail,
                Name = requestedUserName ?? user.Name,
                AccountState = user.AccountState,
                EmailVerifiedAt = now,
                TenantId = invitation.TenantId
            };
            await _dependencies.UserRepository.UpdateUserAsync(updatedUser, cancellationToken);
            user = updatedUser;
        }

        return new AcceptedInvitationUser(user, IsNewUser: false);
    }

    private MfaAuthenticationResult CreateSessionIssuanceResult(IUser user)
    {
        return new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user)
        {
            SessionIssuanceProof = AuthenticationSessionIssuanceProof.CreatePrimary(user.Id, null, _dependencies.TimeProvider.GetUtcNow())
        };
    }

    public async Task<Result<RevokeInvitationsByEmailAdministrationResult>> RevokeInvitationsByEmailAsync(RevokeInvitationsByEmailAdministrationRequest request, AuditContext audit,
        Guid currentSessionId, CancellationToken cancellationToken = default)
    {
        if (currentSessionId == Guid.Empty)
            throw new ArgumentException("Current session ID cannot be empty.", nameof(currentSessionId));
        ValidatedRevokeInvitationsByEmailAdministrationRequest validated;
        try
        {
            ValidateRevokeInvitationsByEmail(request);
            ArgumentNullException.ThrowIfNull(audit);
            validated = new(request.Email!, request.Tenant ?? TenantContext.Global, request.IncludeAllTenants, audit);
        }
        catch (ArgumentException exception)
        {
            return Result.Failure<RevokeInvitationsByEmailAdministrationResult>(AshlarFailureCodes.ValidationError, exception.Message);
        }

        var sanitizedEmail = IdentityNormalization.SanitizeEmailForDelivery(validated.Email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(sanitizedEmail);

        await using var transaction = await _dependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);
        var (revokedCount, complete) = await RevokePendingInvitationsAsync(
            sanitizedEmail, validated.Tenant, validated.IncludeAllTenants, cancellationToken);
        if (!complete)
        {
            return Result.Failure<RevokeInvitationsByEmailAdministrationResult>(AshlarFailureCodes.ConcurrencyConflict);
        }
        var auditTenantId = validated.IncludeAllTenants ? null : validated.Tenant.TenantId;
        var tenantScope = validated.Tenant.TenantId.HasValue ? "tenant" : "global";
        if (validated.IncludeAllTenants)
        {
            tenantScope = "all";
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationRevoked,
            Outcome = SecurityEventOutcomes.Success,
            TenantId = auditTenantId,
            SessionId = currentSessionId,
            Audit = validated.Audit,
            Properties = AddEmailIfEnabled(new Dictionary<string, string>
            {
                ["count"] = revokedCount.ToString(CultureInfo.InvariantCulture),
                ["tenant_scope"] = tenantScope
            }, normalizedEmail)
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(new RevokeInvitationsByEmailAdministrationResult(revokedCount));
    }

    private async Task<(int Count, bool Complete)> RevokePendingInvitationsAsync(
        string email, TenantContext tenant, bool includeAllTenants, CancellationToken cancellationToken)
    {
        var count = 0;
        var now = _dependencies.TimeProvider.GetUtcNow();
        if (now == DateTimeOffset.MinValue)
        {
            return (0, true);
        }
        while (true)
        {
            var pending = await _dependencies.InvitationRepository.SearchInvitationsAsync(new SearchInvitationsRequest
            {
                Email = email,
                Status = InvitationAdministrationStatus.Pending,
                Tenant = includeAllTenants ? null : tenant,
                IncludeAllTenants = includeAllTenants,
                CreatedTo = now.AddTicks(-1),
                Limit = InvitationAdministrationService.MaximumLimit
            }, now, cancellationToken);

            if (pending.Count == 0)
            {
                return (count, true);
            }

            var pageCount = await RevokePendingInvitationPageAsync(
                pending, tenant, includeAllTenants, now, cancellationToken);
            count += pageCount;

            if (pageCount == 0)
            {
                return (count, false);
            }
        }
    }

    private async Task<int> RevokePendingInvitationPageAsync(
        IReadOnlyList<InvitationAdministrationSummary> pending,
        TenantContext tenant,
        bool includeAllTenants,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var count = 0;
        foreach (var invitation in pending)
        {
            var result = await _dependencies.InvitationRepository.RevokeInvitationByIdAsync(
                new RevokeInvitationByIdAdministrationRequest(
                    invitation.Id, includeAllTenants ? null : tenant, includeAllTenants), now, cancellationToken);
            if (result?.RevocationStatus == InvitationAdministrationRevocationStatus.Revoked)
            {
                count++;
            }
        }

        return count;
    }

    private Dictionary<string, string> AddEmailIfEnabled(Dictionary<string, string> properties, string email)
    {
        if (_options.Value.StoreEmailInAudit)
        {
            properties["email"] = email;
        }

        return properties;
    }

    public void ValidateCreateInvitation(CreateInvitationRequest request, Uri callbackBaseUri)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(callbackBaseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);
        IdentityNormalization.SanitizeEmailForDelivery(request.Email);
        _dependencies.UriValidator.ValidateOrThrow(callbackBaseUri);
    }

    public void ValidateRevokeInvitationsByEmail(RevokeInvitationsByEmailAdministrationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        IdentityNormalization.SanitizeEmailForDelivery(request.Email);
    }

    private sealed record AcceptedInvitationUser(IUser User, bool IsNewUser);

    private sealed record ValidatedRevokeInvitationsByEmailAdministrationRequest(
        string Email,
        TenantContext Tenant,
        bool IncludeAllTenants,
        AuditContext Audit);
}

internal interface IInvitationMutationExecutor
{
    void ValidateCreateInvitation(CreateInvitationRequest request, Uri callbackBaseUri);
    void ValidateRevokeInvitationsByEmail(RevokeInvitationsByEmailAdministrationRequest request);
    Task<Result> CreateInvitationAsync(CreateInvitationRequest request, Uri callbackBaseUri,
        AuthenticationContext context, CancellationToken cancellationToken = default);
    Task<Result<RevokeInvitationsByEmailAdministrationResult>> RevokeInvitationsByEmailAsync(RevokeInvitationsByEmailAdministrationRequest request, AuditContext audit,
        Guid currentSessionId, CancellationToken cancellationToken = default);
}
