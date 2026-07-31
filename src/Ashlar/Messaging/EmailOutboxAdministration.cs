using Ashlar.Auditing;
using Ashlar.Operational;

namespace Ashlar.Messaging;

/// <summary>
/// Provides operator-authorized read and mutating operations for durable email outbox administration.
/// </summary>
/// <remarks>
/// Every operation requires explicit global operational scope, an authenticated operator with authoritative active-session fresh proof, host authorization, and matching audit identity.
/// Implementations never unprotect stored bodies and never return text bodies, HTML bodies, protected body payloads, raw headers, raw metadata, or dispatcher lock owners.
/// </remarks>
public interface IEmailOutboxAdministrationService
{
    /// <summary>
    /// Searches durable email outbox rows using safe administrator projections.
    /// </summary>
    /// <param name="request">Actor, explicit global operational scope, paging, and status filters for the read-only search.</param>
    /// <param name="cancellationToken">A token that can cancel the search before results are returned.</param>
    /// <returns>Matching outbox summaries with body, protected payload, header, metadata, and lock-owner values omitted.</returns>
    Task<EmailOutboxSearchResult> SearchAsync(
        EmailOutboxSearchRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets one durable email outbox row using a safe administrator projection.
    /// </summary>
    /// <param name="request">Actor-bound request with explicit global operational scope for the outbox entry.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup before a result is returned.</param>
    /// <returns>The matching outbox detail, or <see langword="null" /> when no entry exists.</returns>
    Task<EmailOutboxDetail?> GetAsync(
        EmailOutboxDetailRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears terminal failure state so a failed email can be claimed by the normal dispatcher.
    /// </summary>
    /// <param name="request">Outbox entry id, actor context, and explicit global operational scope required for the mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable retry outcome with sensitive recipient and subject metadata suppressed when needed.</returns>
    Task<EmailOutboxOperationResult> RetryAsync(
        EmailOutboxOperationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a terminal failed email as discarded so the normal dispatcher will ignore it.
    /// </summary>
    /// <param name="request">Outbox entry id, actor context, and explicit global operational scope required for the mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable discard outcome with sensitive recipient and subject metadata suppressed when needed.</returns>
    Task<EmailOutboxOperationResult> DiscardAsync(
        EmailOutboxOperationRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Shared implementation for provider-specific email outbox administration operations.
/// </summary>
/// <param name="timeProvider">Clock used for operation timestamps and audit events.</param>
/// <param name="securityEventSink">Durable audit sink used for successful mutating operations. It is required so state changes and audit writes share one atomic boundary.</param>
/// <param name="transactionProvider">Ashlar-owned durable transaction composition used to commit provider mutations with their required audit writes.</param>
/// <param name="administration">Precomposed authorization and audit boundaries.</param>
/// <remarks>
/// Providers supply read projections and conditional storage mutations; this base class centralizes audit requirements, stable no-op classification, and the rule that administration
/// mutations never send emails directly.
/// </remarks>
public abstract class EmailOutboxAdministrationServiceBase(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    AshlarDurableTransactionProvider transactionProvider,
    AshlarOperationalAdministrationContext administration) : IEmailOutboxAdministrationService
{
    private readonly ISecurityEventSink _securityEventSink = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    private readonly AshlarDurableTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly AccountSecurityOperationBoundary _readBoundary =
        (administration ?? throw new ArgumentNullException(nameof(administration))).ReadBoundary;
    private readonly AccountSecurityOperationBoundary _mutationBoundary = administration.MutationBoundary;

    /// <summary>
    /// Gets the clock used by provider queries and mutations.
    /// </summary>
    protected TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public async Task<EmailOutboxSearchResult> SearchAsync(
        EmailOutboxSearchRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            EmailOutboxAdministrationProvider.ValidateSearchRequest(request);
        }
        catch (ArgumentException)
        {
            await _readBoundary.RecordValidatedFailureAsync(
                request?.Actor, null, true, AccountSecurityOperation.SearchEmailOutbox, cancellationToken).ConfigureAwait(false);
            throw;
        }
        if (await _readBoundary.AuthorizeAsync(request.Actor, null, true, Guid.Empty,
                AccountSecurityOperation.SearchEmailOutbox, cancellationToken).ConfigureAwait(false) is not null)
            return new([], request.Limit, request.Offset, false);
        var requestedStatuses = EmailOutboxAdministrationProvider.GetStatuses(request).ToHashSet();
        EmailOutboxAdministrationProviderSearchResult providerResult;
        IReadOnlyList<EmailOutboxSummary> items;
        try
        {
            providerResult = await SearchAuthorizedAsync(request, cancellationToken).ConfigureAwait(false);
            if (providerResult.Items is null || providerResult.Items.Count > request.Limit
                || providerResult.Items.Any(static item => item is null))
                throw new InvalidOperationException("Email outbox provider returned an invalid search page.");
            var ids = new HashSet<Guid>();
            var mapped = new List<EmailOutboxSummary>(providerResult.Items.Count);
            foreach (var item in providerResult.Items)
            {
                if (!requestedStatuses.Contains(item.Status))
                    throw new InvalidOperationException("Email outbox provider returned an entry outside the requested status filter.");
                if (!ids.Add(item.Id))
                    throw new InvalidOperationException("Email outbox provider returned duplicate entries.");
                mapped.Add(EmailOutboxAdministrationProvider.CreateSummary(item));
            }
            items = mapped.AsReadOnly();
        }
        catch
        {
            await _readBoundary.RecordFailureAsync(request.Actor, null, true, AccountSecurityOperation.SearchEmailOutbox).ConfigureAwait(false);
            throw;
        }
        await _readBoundary.RecordSuccessAsync(request.Actor, null, true, AccountSecurityOperation.SearchEmailOutbox).ConfigureAwait(false);
        return new(items, request.Limit, request.Offset, providerResult.HasMore);
    }

    /// <inheritdoc />
    public async Task<EmailOutboxDetail?> GetAsync(EmailOutboxDetailRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            EmailOutboxAdministrationProvider.ValidateDetailRequest(request);
        }
        catch (ArgumentException)
        {
            await _readBoundary.RecordValidatedFailureAsync(
                request?.Actor, null, true, AccountSecurityOperation.ReadEmailOutbox, cancellationToken).ConfigureAwait(false);
            throw;
        }
        if (await _readBoundary.AuthorizeAsync(request.Actor, null, true, Guid.Empty,
                AccountSecurityOperation.ReadEmailOutbox, cancellationToken).ConfigureAwait(false) is not null)
            return null;
        EmailOutboxDetail? result;
        try
        {
            var providerResult = await GetAuthorizedAsync(request.Id, cancellationToken).ConfigureAwait(false);
            result = providerResult is null || providerResult.Id != request.Id
                ? null
                : EmailOutboxAdministrationProvider.CreateDetail(providerResult);
        }
        catch
        {
            await _readBoundary.RecordFailureAsync(request.Actor, null, true, AccountSecurityOperation.ReadEmailOutbox).ConfigureAwait(false);
            throw;
        }
        await (result is null
            ? _readBoundary.RecordFailureAsync(request.Actor, null, true, AccountSecurityOperation.ReadEmailOutbox)
            : _readBoundary.RecordSuccessAsync(request.Actor, null, true, AccountSecurityOperation.ReadEmailOutbox)).ConfigureAwait(false);
        return result;
    }

    /// <summary>Loads a validated and authorized safe search page.</summary>
    /// <param name="request">Validated search filters and actor context.</param>
    /// <param name="cancellationToken">A token that can cancel provider loading.</param>
    /// <returns>The safe provider search page.</returns>
    protected abstract Task<EmailOutboxAdministrationProviderSearchResult> SearchAuthorizedAsync(
        EmailOutboxSearchRequest request, CancellationToken cancellationToken);
    /// <summary>Loads a validated and authorized safe detail projection.</summary>
    /// <param name="id">Outbox entry identifier.</param>
    /// <param name="cancellationToken">A token that can cancel provider loading.</param>
    /// <returns>The safe provider detail, if present.</returns>
    protected abstract Task<EmailOutboxAdministrationProjection?> GetAuthorizedAsync(Guid id, CancellationToken cancellationToken);

    /// <inheritdoc />
    public async Task<EmailOutboxOperationResult> RetryAsync(
        EmailOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            request,
            EmailOutboxOperationStatus.Retried,
            AshlarSecurityEventTypes.EmailOutboxDeliveryRetried,
            RetryFailedAsync,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<EmailOutboxOperationResult> DiscardAsync(
        EmailOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            request,
            EmailOutboxOperationStatus.Discarded,
            AshlarSecurityEventTypes.EmailOutboxDeliveryDiscarded,
            DiscardFailedAsync,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies the provider-specific conditional retry state change without exposing or changing stored message content.
    /// </summary>
    /// <param name="id">The durable email outbox entry id.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The updated safe state, or <see langword="null" /> when no row changed.</returns>
    protected abstract Task<EmailOutboxAdministrationOperationState?> RetryFailedAsync(
        Guid id,
        CancellationToken cancellationToken);

    /// <summary>
    /// Applies the provider-specific conditional discard state change without exposing or changing stored message content.
    /// </summary>
    /// <param name="id">The durable email outbox entry id.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The updated safe state, or <see langword="null" /> when no row changed.</returns>
    protected abstract Task<EmailOutboxAdministrationOperationState?> DiscardFailedAsync(
        Guid id,
        CancellationToken cancellationToken);

    /// <summary>
    /// Loads provider-specific safe state for no-op classification after a conditional mutation changed no rows.
    /// </summary>
    /// <param name="id">The durable email outbox entry id.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup before a result is returned.</param>
    /// <returns>The stored safe state, or <see langword="null" /> when no entry exists.</returns>
    protected abstract Task<EmailOutboxAdministrationOperationState?> LoadOperationStateAsync(
        Guid id,
        CancellationToken cancellationToken);

    private async Task<EmailOutboxOperationResult> ExecuteAsync(
        EmailOutboxOperationRequest request,
        EmailOutboxOperationStatus successStatus,
        string eventType,
        Func<Guid, CancellationToken, Task<EmailOutboxAdministrationOperationState?>> applyAsync,
        CancellationToken cancellationToken)
    {
        EmailOutboxAdministrationProvider.ValidateOperationRequest(request);
        var operation = successStatus == EmailOutboxOperationStatus.Retried
            ? AccountSecurityOperation.RetryEmailOutboxDelivery
            : AccountSecurityOperation.DiscardEmailOutboxDelivery;
        if (await _mutationBoundary.AuthorizeAsync(
                request.Actor, null, true, Guid.Empty, operation, cancellationToken).ConfigureAwait(false) is not null)
            return new(EmailOutboxOperationStatus.Failed, request.Id);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var state = await applyAsync(request.Id, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return await ClassifyNoOpAsync(request.Id, cancellationToken).ConfigureAwait(false);
        }
        if (state.Id != request.Id)
            throw new InvalidOperationException("Email outbox provider returned state for a different entry.");
        ValidateOperationState(state);
        var expectedStatus = successStatus == EmailOutboxOperationStatus.Retried
            ? EmailOutboxStatus.Pending
            : EmailOutboxStatus.Discarded;
        if (state.Status != expectedStatus)
            throw new InvalidOperationException("Email outbox provider returned an invalid post-operation state.");

        var result = EmailOutboxAdministrationProvider.CreateOperationResult(successStatus, state);
        await EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(
            _securityEventSink,
            TimeProvider,
            eventType,
            request,
            result,
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

        return result;
    }

    private async Task<EmailOutboxOperationResult> ClassifyNoOpAsync(Guid id, CancellationToken cancellationToken)
    {
        var state = await LoadOperationStateAsync(id, cancellationToken).ConfigureAwait(false);
        if (state is not null && state.Id != id)
            throw new InvalidOperationException("Email outbox provider returned state for a different entry.");
        if (state is not null)
        {
            ValidateOperationState(state);
            if (state.Status == EmailOutboxStatus.Failed)
                throw new InvalidOperationException("Email outbox provider returned an unchanged failed state.");
        }
        return EmailOutboxAdministrationProvider.CreateNoOpResult(id, state);
    }

    private static void ValidateOperationState(EmailOutboxAdministrationOperationState state)
    {
        if (!Enum.IsDefined(state.Status)
            || !Enum.IsDefined(state.Sensitivity)
            || !Enum.IsDefined(state.BodyProtection))
            throw new InvalidOperationException("Email outbox provider returned invalid operation state.");
    }
}

/// <summary>
/// Paging and status filters for safe email outbox browsing.
/// </summary>
public sealed record EmailOutboxSearchRequest
{
    /// <summary>Gets the authenticated operator context.</summary>
    public AccountSecurityActorContext Actor { get; init; } = null!;
    /// <summary>Gets the required global operational scope.</summary>
    public required OperationalAdministrationScope Scope { get; init; }
    /// <summary>
    /// Maximum number of entries that can be requested.
    /// </summary>
    public const int MaximumLimit = 100;

    /// <summary>
    /// Gets the default number of entries returned.
    /// </summary>
    public const int DefaultLimit = 50;

    /// <summary>
    /// Gets the requested status filter. Empty means all administrator-browseable statuses are included.
    /// </summary>
    public IReadOnlySet<EmailOutboxStatus>? Statuses { get; init; }

    /// <summary>
    /// Gets the maximum number of entries to return.
    /// </summary>
    public int Limit { get; init; } = DefaultLimit;

    /// <summary>
    /// Gets the number of entries to skip.
    /// </summary>
    public int Offset { get; init; }
}

/// <summary>Request bound to an operator for one global email outbox projection.</summary>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="Actor">The authenticated operator context.</param>
/// <param name="Scope">The required global operational scope.</param>
public sealed record EmailOutboxDetailRequest(Guid Id, AccountSecurityActorContext Actor, OperationalAdministrationScope Scope);

/// <summary>
/// Safe email outbox status values exposed to administrators.
/// </summary>
public enum EmailOutboxStatus
{
    /// <summary>
    /// The entry is available for dispatch.
    /// </summary>
    Pending,

    /// <summary>
    /// The entry is waiting for a future retry time.
    /// </summary>
    Scheduled,

    /// <summary>
    /// The entry is currently locked by a dispatcher.
    /// </summary>
    Locked,

    /// <summary>
    /// The entry has an expired dispatcher lock.
    /// </summary>
    ExpiredLock,

    /// <summary>
    /// The entry has reached terminal failure.
    /// </summary>
    Failed,

    /// <summary>
    /// The entry was delivered.
    /// </summary>
    Sent,

    /// <summary>
    /// The entry was manually discarded.
    /// </summary>
    Discarded
}

/// <summary>
/// Body-free and payload-free summary of a durable email outbox entry.
/// </summary>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="ToAddress">The recipient address, omitted when sensitive.</param>
/// <param name="Subject">The message subject, omitted when sensitive.</param>
/// <param name="Status">The derived outbox status.</param>
/// <param name="Sensitivity">The persisted message sensitivity.</param>
/// <param name="AttemptCount">The attempted delivery count.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastAttemptAt">The last attempt timestamp.</param>
/// <param name="FailedAt">The terminal failure timestamp.</param>
/// <param name="LastErrorSummary">Single-line truncated failure summary, suppressed for protected or live-secret messages.</param>
public sealed record EmailOutboxSummary(
    Guid Id,
    string? ToAddress,
    string? Subject,
    EmailOutboxStatus Status,
    EmailMessageSensitivity Sensitivity,
    int AttemptCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset AvailableAt,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? FailedAt,
    string? LastErrorSummary);

/// <summary>
/// Body-free and payload-free detail of a durable email outbox entry.
/// </summary>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="ToAddress">The recipient address, omitted when sensitive.</param>
/// <param name="FromAddress">The sender address, omitted when sensitive.</param>
/// <param name="ReplyToAddress">The reply-to address, omitted when sensitive.</param>
/// <param name="CcAddress">The CC address list, omitted when sensitive.</param>
/// <param name="Subject">The message subject, omitted when sensitive.</param>
/// <param name="Status">The derived outbox status.</param>
/// <param name="Sensitivity">The persisted message sensitivity.</param>
/// <param name="BodyProtection">The persisted body protection marker.</param>
/// <param name="HasTextBody">Whether a text body exists without exposing its contents.</param>
/// <param name="HasHtmlBody">Whether an HTML body exists without exposing its contents.</param>
/// <param name="AttemptCount">The attempted delivery count.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastAttemptAt">The last attempt timestamp.</param>
/// <param name="FailedAt">The terminal failure timestamp.</param>
/// <param name="SentAt">The sent timestamp.</param>
/// <param name="DiscardedAt">The discarded timestamp.</param>
/// <param name="LastErrorSummary">Single-line truncated failure summary, suppressed for protected or live-secret messages.</param>
public sealed record EmailOutboxDetail(
    Guid Id,
    string? ToAddress,
    string? FromAddress,
    string? ReplyToAddress,
    string? CcAddress,
    string? Subject,
    EmailOutboxStatus Status,
    EmailMessageSensitivity Sensitivity,
    EmailOutboxBodyProtection BodyProtection,
    bool HasTextBody,
    bool HasHtmlBody,
    int AttemptCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset AvailableAt,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? FailedAt,
    DateTimeOffset? SentAt,
    DateTimeOffset? DiscardedAt,
    string? LastErrorSummary);

/// <summary>
/// Paged email outbox search result.
/// </summary>
/// <param name="Items">Safe summaries returned for this page.</param>
/// <param name="Limit">Maximum number of <paramref name="Items" /> requested.</param>
/// <param name="Offset">Number of <paramref name="Items" /> skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record EmailOutboxSearchResult(
    IReadOnlyList<EmailOutboxSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for an audited durable email outbox mutation.
/// </summary>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="Actor">Authenticated operator context containing matching required audit metadata.</param>
/// <param name="Scope">The required global operational scope.</param>
public sealed record EmailOutboxOperationRequest(
    Guid Id,
    AccountSecurityActorContext Actor,
    OperationalAdministrationScope Scope);

/// <summary>
/// Safe result statuses for manual durable email outbox operations.
/// </summary>
public enum EmailOutboxOperationStatus
{
    /// <summary>
    /// The entry was moved back to dispatchable retry state.
    /// </summary>
    Retried,

    /// <summary>
    /// The entry was marked discarded.
    /// </summary>
    Discarded,

    /// <summary>
    /// No entry exists for the requested id.
    /// </summary>
    NotFound,

    /// <summary>
    /// The entry exists but is not in terminal failed state.
    /// </summary>
    NotFailed,

    /// <summary>
    /// The entry was already discarded.
    /// </summary>
    AlreadyDiscarded,

    /// <summary>
    /// The operation could not complete after validating the request.
    /// </summary>
    Failed
}

/// <summary>
/// Safe result for a manual durable email outbox mutation.
/// </summary>
/// <param name="Status">Stable mutation outcome.</param>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="ToAddress">The recipient address, omitted when unsafe.</param>
/// <param name="Subject">The message subject, omitted when unsafe.</param>
/// <param name="OutboxStatus">The observed outbox state used during no-op classification.</param>
public sealed record EmailOutboxOperationResult(
    EmailOutboxOperationStatus Status,
    Guid Id,
    string? ToAddress = null,
    string? Subject = null,
    EmailOutboxStatus? OutboxStatus = null);

/// <summary>
/// Stored metadata used to classify and report durable email outbox mutations without exposing message content.
/// </summary>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="ToAddress">Stored recipient address used only when public fields are not suppressed.</param>
/// <param name="Subject">Stored message subject used only when public fields are not suppressed.</param>
/// <param name="Status">The stored outbox status.</param>
/// <param name="Sensitivity">Persisted message sensitivity.</param>
/// <param name="BodyProtection">Persisted body-protection marker.</param>
public sealed record EmailOutboxAdministrationOperationState(
    Guid Id,
    string? ToAddress,
    string? Subject,
    EmailOutboxStatus Status,
    EmailMessageSensitivity Sensitivity,
    EmailOutboxBodyProtection BodyProtection);

/// <summary>Provider-facing projection containing only fields safe to pass into administration mapping helpers.</summary>
/// <param name="Id">Outbox entry id.</param>
/// <param name="ToAddress">Recipient address when safe.</param>
/// <param name="FromAddress">Sender address when safe.</param>
/// <param name="ReplyToAddress">Reply-to address when safe.</param>
/// <param name="CcAddress">CC address list when safe.</param>
/// <param name="Subject">Subject when safe.</param>
/// <param name="HasTextBody">Whether a text body exists.</param>
/// <param name="HasHtmlBody">Whether an HTML body exists.</param>
/// <param name="Sensitivity">Persisted sensitivity.</param>
/// <param name="BodyProtection">Persisted body-protection marker.</param>
/// <param name="Status">Derived outbox status.</param>
/// <param name="AttemptCount">Delivery attempt count.</param>
/// <param name="CreatedAt">Creation timestamp.</param>
/// <param name="AvailableAt">Availability timestamp.</param>
/// <param name="LastAttemptAt">Last-attempt timestamp.</param>
/// <param name="FailedAt">Failure timestamp.</param>
/// <param name="SentAt">Delivery timestamp.</param>
/// <param name="DiscardedAt">Discard timestamp.</param>
/// <param name="LastErrorSummary">Pre-sanitized failure summary.</param>
public sealed record EmailOutboxAdministrationProjection(
    Guid Id,
    string? ToAddress,
    string? FromAddress,
    string? ReplyToAddress,
    string? CcAddress,
    string? Subject,
    bool HasTextBody,
    bool HasHtmlBody,
    EmailMessageSensitivity Sensitivity,
    EmailOutboxBodyProtection BodyProtection,
    EmailOutboxStatus Status,
    int AttemptCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset AvailableAt,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? FailedAt,
    DateTimeOffset? SentAt,
    DateTimeOffset? DiscardedAt,
    string? LastErrorSummary);

/// <summary>Provider search page mapped to public summaries by the actor-bound service base.</summary>
/// <param name="Items">Safe provider projections for the requested page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record EmailOutboxAdministrationProviderSearchResult(
    IReadOnlyList<EmailOutboxAdministrationProjection> Items,
    bool HasMore);

/// <summary>
/// Provider-facing validation, projection, and audit helpers for email outbox administration implementations.
/// </summary>
public static class EmailOutboxAdministrationProvider
{
    /// <summary>
    /// Maximum number of characters exposed from stored failure details.
    /// </summary>
    public const int MaxLastErrorSummaryLength = 256;

    /// <summary>
    /// Generic failure summary used when message content may contain live secrets or protected payloads.
    /// </summary>
    public const string SensitiveFailureSummary = "Email outbox delivery failed. Error details were suppressed because the message may contain sensitive content.";

    /// <summary>
    /// Gets all administrator-browseable statuses.
    /// </summary>
    public static IReadOnlySet<EmailOutboxStatus> DefaultStatuses { get; } =
        Enum.GetValues<EmailOutboxStatus>().ToHashSet();

    /// <summary>
    /// Ensures a search request uses supported paging and status filters.
    /// </summary>
    /// <param name="request">Search request to validate.</param>
    public static void ValidateSearchRequest(EmailOutboxSearchRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateActorAndScope(request.Actor, request.Scope);
        if (request.Limit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Limit, "Limit must be greater than zero.");
        }

        if (request.Limit > EmailOutboxSearchRequest.MaximumLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Limit, "Limit cannot exceed the maximum limit.");
        }

        if (request.Offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Offset, "Offset cannot be negative.");
        }

        var unsupportedStatus = request.Statuses?.Where(static status => !Enum.IsDefined(status)).Cast<EmailOutboxStatus?>().FirstOrDefault();
        if (unsupportedStatus.HasValue)
        {
            throw new ArgumentOutOfRangeException(nameof(request), unsupportedStatus.Value, "Status is not supported.");
        }
    }

    /// <summary>Validates an actor-bound detail request.</summary>
    /// <param name="request">Detail request to validate.</param>
    public static void ValidateDetailRequest(EmailOutboxDetailRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Id == Guid.Empty)
            throw new ArgumentException("Email outbox entry ID cannot be empty.", nameof(request));
        ValidateActorAndScope(request.Actor, request.Scope);
    }

    /// <summary>
    /// Gets the status filter for a request.
    /// </summary>
    /// <param name="request">Search request whose explicit or default status set is needed.</param>
    /// <returns>The effective status set.</returns>
    public static IReadOnlySet<EmailOutboxStatus> GetStatuses(EmailOutboxSearchRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Statuses is { Count: > 0 } ? request.Statuses : DefaultStatuses;
    }

    /// <summary>
    /// Validates a manual operation request and its required audit context.
    /// </summary>
    /// <param name="request">Mutation request to validate.</param>
    public static void ValidateOperationRequest(EmailOutboxOperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Id == Guid.Empty)
        {
            throw new ArgumentException("Email outbox entry ID cannot be empty.", nameof(request));
        }

        ValidateActorAndScope(request.Actor, request.Scope);
    }

    /// <summary>Creates a safe public summary from a safe provider projection.</summary>
    /// <param name="record">Safe provider projection.</param>
    /// <returns>The public administration summary.</returns>
    public static EmailOutboxSummary CreateSummary(EmailOutboxAdministrationProjection record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateProjection(record);

        return new EmailOutboxSummary(
            record.Id,
            SuppressWhenSensitive(record.ToAddress, record),
            SuppressWhenSensitive(record.Subject, record),
            record.Status,
            record.Sensitivity,
            record.AttemptCount,
            record.CreatedAt,
            record.AvailableAt,
            record.LastAttemptAt,
            record.FailedAt,
            CreateLastErrorSummary(record));
    }

    /// <summary>Creates safe public detail from a safe provider projection.</summary>
    /// <param name="record">Safe provider projection.</param>
    /// <returns>The public administration detail.</returns>
    public static EmailOutboxDetail CreateDetail(EmailOutboxAdministrationProjection record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateProjection(record);

        return new EmailOutboxDetail(
            record.Id,
            SuppressWhenSensitive(record.ToAddress, record),
            SuppressWhenSensitive(record.FromAddress, record),
            SuppressWhenSensitive(record.ReplyToAddress, record),
            SuppressWhenSensitive(record.CcAddress, record),
            SuppressWhenSensitive(record.Subject, record),
            record.Status,
            record.Sensitivity,
            record.BodyProtection,
            record.HasTextBody,
            record.HasHtmlBody,
            record.AttemptCount,
            record.CreatedAt,
            record.AvailableAt,
            record.LastAttemptAt,
            record.FailedAt,
            record.SentAt,
            record.DiscardedAt,
            CreateLastErrorSummary(record));
    }

    /// <summary>Gets the pre-sanitized failure summary from a provider projection.</summary>
    /// <param name="record">Safe provider projection.</param>
    /// <returns>The pre-sanitized failure summary.</returns>
    public static string? CreateLastErrorSummary(EmailOutboxAdministrationProjection record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return CreateLastErrorSummary(record.LastErrorSummary, record.Sensitivity, record.BodyProtection);
    }

    /// <summary>Sanitizes stored provider failure detail before it enters a public provider projection.</summary>
    /// <param name="lastError">Stored provider failure detail.</param>
    /// <param name="sensitivity">Persisted sensitivity.</param>
    /// <param name="bodyProtection">Persisted body-protection marker.</param>
    /// <returns>A safe single-line bounded summary.</returns>
    public static string? CreateLastErrorSummary(
        string? lastError,
        EmailMessageSensitivity sensitivity,
        EmailOutboxBodyProtection bodyProtection)
    {
        if (lastError is null)
        {
            return null;
        }

        if (sensitivity != EmailMessageSensitivity.Normal || bodyProtection != EmailOutboxBodyProtection.None)
        {
            return SensitiveFailureSummary;
        }

        var summary = lastError.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (summary.Length > MaxLastErrorSummaryLength)
        {
            summary = summary[..MaxLastErrorSummaryLength];
        }

        return summary;
    }

    /// <summary>
    /// Parses a provider-derived status name defensively.
    /// </summary>
    /// <param name="status">The provider-derived status name.</param>
    /// <returns>The parsed status, or <see cref="EmailOutboxStatus.Pending" /> for unknown values.</returns>
    public static EmailOutboxStatus ParseStatus(string? status)
    {
        return Enum.TryParse<EmailOutboxStatus>(status, ignoreCase: false, out var parsed)
            && Enum.IsDefined(parsed)
            ? parsed
            : EmailOutboxStatus.Pending;
    }

    internal static EmailOutboxOperationResult CreateOperationResult(
        EmailOutboxOperationStatus status,
        Guid id,
        bool suppressPublicFields,
        string? toAddress = null,
        string? subject = null,
        EmailOutboxStatus? outboxStatus = null)
    {
        return new EmailOutboxOperationResult(
            status,
            id,
            suppressPublicFields ? null : NullIfUnsafeMultiline(toAddress),
            suppressPublicFields ? null : NullIfUnsafeMultiline(subject),
            outboxStatus);
    }

    internal static EmailOutboxOperationResult CreateOperationResult(
        EmailOutboxOperationStatus status,
        EmailOutboxAdministrationOperationState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var suppressPublicFields = state.Sensitivity != EmailMessageSensitivity.Normal
            || state.BodyProtection != EmailOutboxBodyProtection.None;
        return CreateOperationResult(status, state.Id, suppressPublicFields, state.ToAddress, state.Subject, state.Status);
    }

    internal static EmailOutboxOperationResult CreateNoOpResult(
        Guid id, EmailOutboxAdministrationOperationState? state)
    {
        if (state is null)
        {
            return CreateOperationResult(EmailOutboxOperationStatus.NotFound, id, suppressPublicFields: true);
        }

        var status = state.Status == EmailOutboxStatus.Discarded
            ? EmailOutboxOperationStatus.AlreadyDiscarded
            : EmailOutboxOperationStatus.NotFailed;
        var suppressPublicFields = state.Sensitivity != EmailMessageSensitivity.Normal
            || state.BodyProtection != EmailOutboxBodyProtection.None;
        return CreateOperationResult(status, state.Id, suppressPublicFields, state.ToAddress, state.Subject, state.Status);
    }

    internal static async Task RecordSuccessfulOperationAsync(
        ISecurityEventSink sink,
        TimeProvider timeProvider,
        string eventType,
        EmailOutboxOperationRequest request,
        EmailOutboxOperationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);

        await SecurityEventAuditEmission.RecordCompletedOperationAsync(
            sink,
            timeProvider,
            eventType,
            request.Actor.Audit,
            new Dictionary<string, string> { ["email_outbox_id"] = result.Id.ToString("D") },
            cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateActorAndScope(AccountSecurityActorContext actor, OperationalAdministrationScope scope)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (scope != OperationalAdministrationScope.Global)
            throw new ArgumentException("Email outbox administration requires global operational scope.", nameof(scope));
    }

    private static bool IsSensitive(EmailOutboxAdministrationProjection record)
    {
        return record.Sensitivity != EmailMessageSensitivity.Normal ||
            record.BodyProtection != EmailOutboxBodyProtection.None;
    }

    private static string? SuppressWhenSensitive(string? value, EmailOutboxAdministrationProjection record)
    {
        return IsSensitive(record) ? null : NullIfUnsafeMultiline(value);
    }

    private static string? NullIfUnsafeMultiline(string? value)
    {
        return string.IsNullOrWhiteSpace(value) || value.Contains('\r') || value.Contains('\n') ? null : value;
    }

    private static void ValidateProjection(EmailOutboxAdministrationProjection record)
    {
        if (record.Id == Guid.Empty)
            throw new InvalidOperationException("Email outbox provider returned an empty entry ID.");
        if (!Enum.IsDefined(record.Status))
            throw new InvalidOperationException("Email outbox provider returned an invalid status.");
        if (!Enum.IsDefined(record.Sensitivity))
            throw new InvalidOperationException("Email outbox provider returned an invalid sensitivity.");
        if (!Enum.IsDefined(record.BodyProtection))
            throw new InvalidOperationException("Email outbox provider returned an invalid body-protection marker.");
        if (record.AttemptCount < 0)
            throw new InvalidOperationException("Email outbox provider returned a negative attempt count.");
    }
}
