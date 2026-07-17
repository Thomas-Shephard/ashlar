using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Features.Infrastructure;
using Ashlar.Identity.Models.Credentials;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Models.Tenants;

namespace Ashlar.OAuth;

internal interface IExternalAccountCredentialLinker
{
    Task<Result> LinkExternalAccountCredentialAsync(ExternalAccountCredentialLinkRequest request, CancellationToken cancellationToken = default);
}

internal sealed record ExternalAccountCredentialLinkRequest(
    Guid CurrentUserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    FreshMfaVerificationProof? FreshMfaProof,
    Guid? CurrentSessionId,
    TenantContext Tenant,
    AuditContext? Audit = null,
    string? CredentialMetadata = null);

internal sealed class ExternalAccountCredentialLinker : IExternalAccountCredentialLinker
{
    private const string LinkPurpose = "external-account-linking";
    private readonly IUserRepository _users;
    private readonly ICredentialRepository _credentials;
    private readonly IFreshAuthenticationProofValidator _proofValidator;
    private readonly AshlarDurableTransactionProvider _transactions;
    private readonly SecurityEventFanOutSink _events;
    private readonly TimeProvider _timeProvider;

    public ExternalAccountCredentialLinker(
        IUserRepository users,
        ICredentialRepository credentials,
        IFreshAuthenticationProofValidator proofValidator,
        AshlarDurableTransactionProvider transactions,
        SecurityEventFanOutSink securityEventSink,
        TimeProvider? timeProvider = null)
    {
        _users = users ?? throw new ArgumentNullException(nameof(users));
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _proofValidator = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));
        _transactions = transactions ?? throw new ArgumentNullException(nameof(transactions));
        ArgumentNullException.ThrowIfNull(securityEventSink);
        if (!securityEventSink.RequiresDurableTransaction || !ReferenceEquals(transactions, securityEventSink.TransactionProvider))
            throw new ArgumentException("External credential linking requires durable audit using the same transaction provider.", nameof(transactions));
        if (!transactions.IncludesParticipant(users) || !transactions.IncludesParticipant(credentials))
            throw new ArgumentException("External credential repositories must be enlisted in the durable transaction composition.", nameof(transactions));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _events = securityEventSink;
    }

    public async Task<Result> LinkExternalAccountCredentialAsync(ExternalAccountCredentialLinkRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Assertion);
        ArgumentNullException.ThrowIfNull(request.Provider);
        ArgumentNullException.ThrowIfNull(request.Tenant);
        if (request.Audit is null)
            return Result.Failure(AshlarFailureCodes.ValidationError);
        if (request.Provider.Key.Type != ProviderType.OAuth && request.Provider.Key.Type != ProviderType.Oidc)
            return Result.Failure(AshlarFailureCodes.ValidationError);

        if (await _proofValidator.ValidateAsync(request.CurrentUserId, request.Tenant, request.FreshMfaProof, request.CurrentSessionId, LinkPurpose, cancellationToken) is { } proofFailure)
            return Result.Failure(proofFailure);

        await using var transaction = await _transactions.BeginTransactionAsync(cancellationToken);
        await _credentials.AcquireUserMutationLockAsync(request.CurrentUserId, cancellationToken);
        var user = await _users.GetUserByIdAsync(request.CurrentUserId, cancellationToken);
        if (user == null)
            return await FailAsync(AshlarFailureCodes.UserNotFound);
        if (!UserTenantOwnership.Matches(user, request.Tenant.TenantId))
            return await FailAsync(AshlarFailureCodes.TenantMismatch);

        var providerKey = request.Provider.GetProviderKey(request.Assertion, request.CurrentUserId);
        if (string.IsNullOrWhiteSpace(providerKey))
            return await FailAsync(AshlarFailureCodes.InvalidProviderKey);
        var provider = request.Provider.Key;
        var linkedUser = await _users.GetUserByProviderKeyAsync(provider.Type, provider.Name, providerKey, cancellationToken);
        if (linkedUser != null)
            return await FailAsync(linkedUser.Id == request.CurrentUserId ? AshlarFailureCodes.AlreadyLinkedToSelf : AshlarFailureCodes.AlreadyLinkedToOther);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = request.CurrentUserId,
            ProviderType = provider.Type,
            ProviderName = provider.Name,
            ProviderKey = providerKey,
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            Metadata = request.CredentialMetadata
        };
        try
        {
            await _credentials.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        }
        catch (CredentialProviderKeyConflictException)
        {
            return await FailAsync(AshlarFailureCodes.AlreadyLinkedToOther);
        }

        await RecordAsync(SecurityEventOutcomes.Success, provider, null,
            new Dictionary<string, string> { ["credential_id"] = credential.Id.ToString() });
        await transaction.CommitAsync(cancellationToken);
        return Result.Success();

        async Task<Result> FailAsync(AshlarFailureCode failure)
        {
            await RecordAsync(SecurityEventOutcomes.Failure, request.Provider.Key, failure.Value, null);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure(failure);
        }

        Task RecordAsync(string outcome, AuthenticationProviderKey provider, string? failure, IReadOnlyDictionary<string, string>? properties) =>
            _events.RecordAsync(new AshlarSecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                OccurredAt = _timeProvider.GetUtcNow(),
                Outcome = outcome,
                UserId = request.CurrentUserId,
                TenantId = request.Tenant.TenantId,
                ActorUserId = request.Audit!.ActorUserId,
                Provider = provider,
                IpAddress = request.Audit.IpAddress,
                UserAgent = request.Audit.UserAgent,
                CorrelationId = request.Audit.CorrelationId,
                FailureReason = failure,
                Properties = properties
            }, cancellationToken);
    }
}
