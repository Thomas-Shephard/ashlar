using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Ashlar.Identity;

/// <summary>
/// Provides bootstrap service behavior.
/// </summary>
/// <param name="stateRepository">The state repository value.</param>
/// <param name="invitationService">The invitation service value.</param>
/// <param name="invitationDependencies">The invitation dependencies value.</param>
/// <param name="grantService">The grant service value.</param>
/// <param name="options">The options value.</param>
/// <param name="notificationService">The notification service value.</param>
public sealed class BootstrapService(
    IBootstrapStateRepository stateRepository,
    IInvitationService invitationService,
    InvitationDependencies invitationDependencies,
    IAuthorizationGrantService grantService,
    IOptions<BootstrapOptions>? options = null,
    ISecurityNotificationService? notificationService = null)
    : IBootstrapService
{
    private const string BootstrapMetadataKey = "ashlar.bootstrap";
    private readonly IBootstrapStateRepository _stateRepository = stateRepository ?? throw new ArgumentNullException(nameof(stateRepository));
    private readonly IInvitationService _invitationService = invitationService ?? throw new ArgumentNullException(nameof(invitationService));
    private readonly InvitationDependencies _invitationDependencies = invitationDependencies ?? throw new ArgumentNullException(nameof(invitationDependencies));
    private readonly IAuthorizationGrantService _grantService = grantService ?? throw new ArgumentNullException(nameof(grantService));
    private readonly IOptions<BootstrapOptions> _options = options ?? Options.Create(new BootstrapOptions());
    private readonly SecurityEventEmitter _securityEvents = new(invitationDependencies.SecurityEventSink, invitationDependencies.TimeProvider);
    private readonly SecurityNotificationEmitter _notifications = new(notificationService);

    /// <summary>
    /// Performs the get status <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task<BootstrapStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        return _stateRepository.GetBootstrapStatusAsync(cancellationToken);
    }

    /// <summary>
    /// Performs the create bootstrap invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result<string>> CreateBootstrapInvitationAsync(CreateBootstrapInvitationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (await GetStatusAsync(cancellationToken) == BootstrapStatus.Initialized)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapInvitationCreated,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Properties = new Dictionary<string, string> { ["email"] = request.Email }
            }, cancellationToken);
            return Result.Failure<string>(AshlarFailureCodes.AlreadyInitialized);
        }

        var token = _invitationDependencies.TokenGenerator.GenerateToken();
        var tokenHash = _invitationDependencies.TokenHasher.HashToken(token);
        var now = _invitationDependencies.TimeProvider.GetUtcNow();
        var email = IdentityNormalization.SanitizeEmailForDelivery(request.Email);
        var normalizedEmail = IdentityNormalization.NormalizeEmail(email);

        var metadataDict = new Dictionary<string, object>();
        if (!string.IsNullOrWhiteSpace(request.Metadata))
        {
            try
            {
                var existingMetadata = JsonSerializer.Deserialize<Dictionary<string, object>>(request.Metadata);
                if (existingMetadata != null)
                {
                    metadataDict = existingMetadata;
                }
            }
            catch (JsonException)
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.BootstrapInvitationCreated,
                    Outcome = SecurityEventOutcomes.Failure,
                    FailureReason = AshlarFailureCodes.InvalidMetadataFormat.Value,
                    Properties = new Dictionary<string, string> { ["email"] = email }
                }, cancellationToken);
                return Result.Failure<string>(AshlarFailureCodes.InvalidMetadataFormat);
            }
        }
        metadataDict[BootstrapMetadataKey] = true;
        var metadata = JsonSerializer.Serialize(metadataDict);

        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = email,
            TenantId = request.TenantId,
            TokenHash = tokenHash,
            CreatedAt = now,
            UpdatedAt = now,
            ExpiresAt = now.Add(request.Expiry ?? TimeSpan.FromHours(24)), // Default bootstrap expiry
            Metadata = metadata,
            Version = Guid.NewGuid().ToString()
        };

        await using var transaction = await _invitationDependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        // Ensure we are still uninitialized within the transaction if the repo supports it.
        // For now, we rely on the repository implementation to handle concurrency if it can.

        await _invitationDependencies.InvitationRepository.RevokeInvitationsByEmailAsync(
            normalizedEmail,
            request.TenantId,
            cancellationToken);

        await _invitationDependencies.InvitationRepository.CreateInvitationAsync(invitation, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapInvitationCreated,
                Outcome = SecurityEventOutcomes.Success,
                Properties = new Dictionary<string, string>
                {
                    ["invitation_id"] = invitation.Id.ToString(),
                    ["email"] = email
                }
            }, ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(token);
    }

    /// <summary>
    /// Performs the accept bootstrap invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<Result<Guid>> AcceptBootstrapInvitationAsync(AcceptInvitationRequest request, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var tokenHash = _invitationDependencies.TokenHasher.HashToken(request.Token);
        var invitation = await _invitationDependencies.InvitationRepository.GetInvitationByTokenHashAsync(tokenHash, cancellationToken);

        if (invitation == null || !invitation.IsAvailable(_invitationDependencies.TimeProvider.GetUtcNow()))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.InvalidInvitation.Value,
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.InvalidInvitation);
        }

        if (!IsBootstrapInvitation(invitation))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.NotBootstrapInvitation.Value,
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.NotBootstrapInvitation);
        }

        if (await GetStatusAsync(cancellationToken) == BootstrapStatus.Initialized)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.AlreadyInitialized);
        }

        var now = _invitationDependencies.TimeProvider.GetUtcNow();

        // We use a transaction to ensure atomicity of invitation acceptance, grant assignment, and state update.
        await using var transaction = await _invitationDependencies.TransactionProvider.BeginTransactionAsync(cancellationToken);

        var result = await _invitationService.AcceptInvitationAsync(request, context, cancellationToken);

        if (!result.Succeeded || result.Value == Guid.Empty)
        {
            return result;
        }

        var userId = result.Value;

        // Assign configured grants
        foreach (var template in _options.Value.Grants)
        {
            var grantResult = await _grantService.CreateGrantAsync(new CreateAuthorizationGrantRequest(
                UserId: userId,
                TenantId: template.TenantId,
                ScopeType: template.ScopeType,
                ScopeId: template.ScopeId,
                Role: template.Role,
                Permission: template.Permission
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
                    Context = context
                }, cancellationToken);
                return Result.Failure<Guid>(grantResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.GrantCreationFailed));
            }
        }

        // Mark as initialized
        var initialized = await _stateRepository.MarkAsInitializedAsync(userId, now, cancellationToken);
        if (!initialized)
        {
            // This should only happen if someone else initialized the system concurrently.
            await transaction.RollbackAsync(cancellationToken);
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = AshlarFailureCodes.AlreadyInitialized.Value,
                Context = context
            }, cancellationToken);
            return Result.Failure<Guid>(AshlarFailureCodes.AlreadyInitialized);
        }

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.BootstrapCompleted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                Context = context
            }, ct);

            var notifiedUser = await _invitationDependencies.IdentityRepository.GetUserByIdAsync(userId, ct);
            if (notifiedUser != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.BootstrapCompleted, notifiedUser, now, context: context, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);

        return result;
    }

    private static bool IsBootstrapInvitation(UserInvitation invitation)
    {
        if (string.IsNullOrWhiteSpace(invitation.Metadata))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(invitation.Metadata);
            return doc.RootElement.TryGetProperty(BootstrapMetadataKey, out var prop) && prop.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
