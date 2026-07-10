using Ashlar.Auditing;

namespace Ashlar.Messaging;

/// <summary>
/// Provides read-only and audited mutating operations for durable email outbox administration.
/// </summary>
/// <remarks>
/// Hosts are responsible for authorizing access, applying any step-up authentication required for operators, and auditing calls at the application boundary. Implementations never unprotect
/// stored bodies and never return text bodies, HTML bodies, protected body payloads, raw headers, raw metadata, or dispatcher lock owners.
/// </remarks>
public interface IEmailOutboxAdministrationService
{
    /// <summary>
    /// Searches durable email outbox rows using safe administrator projections.
    /// </summary>
    /// <param name="request">Paging and status filters for the read-only search.</param>
    /// <param name="cancellationToken">A token that can cancel the search before results are returned.</param>
    /// <returns>Matching outbox summaries with body, protected payload, header, metadata, and lock-owner values omitted.</returns>
    Task<EmailOutboxSearchResult> SearchAsync(
        EmailOutboxSearchRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets one durable email outbox row using a safe administrator projection.
    /// </summary>
    /// <param name="id">The outbox entry id.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup before a result is returned.</param>
    /// <returns>The matching outbox detail, or <see langword="null" /> when no entry exists.</returns>
    Task<EmailOutboxDetail?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears terminal failure state so a failed email can be claimed by the normal dispatcher.
    /// </summary>
    /// <param name="request">Outbox entry id and audit context required for the mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable retry outcome with sensitive recipient and subject metadata suppressed when needed.</returns>
    Task<EmailOutboxOperationResult> RetryAsync(
        EmailOutboxOperationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a terminal failed email as discarded so the normal dispatcher will ignore it.
    /// </summary>
    /// <param name="request">Outbox entry id and audit context required for the mutation.</param>
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
/// <param name="transactionProvider">Transaction provider used to commit provider mutations with their required audit writes. It is required for every mutating operation.</param>
/// <remarks>
/// Providers supply read projections and conditional storage mutations; this base class centralizes audit requirements, stable no-op classification, and the rule that administration
/// mutations never send emails directly.
/// </remarks>
public abstract class EmailOutboxAdministrationServiceBase(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    IAshlarTransactionProvider transactionProvider) : IEmailOutboxAdministrationService
{
    private readonly ISecurityEventSink _securityEventSink = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));

    /// <summary>
    /// Gets the clock used by provider queries and mutations.
    /// </summary>
    protected TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public abstract Task<EmailOutboxSearchResult> SearchAsync(
        EmailOutboxSearchRequest request,
        CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract Task<EmailOutboxDetail?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default);

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

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var state = await applyAsync(request.Id, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return await ClassifyNoOpAsync(request.Id, cancellationToken).ConfigureAwait(false);
        }

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
        return EmailOutboxAdministrationProvider.CreateNoOpResult(id, state);
    }
}

/// <summary>
/// Paging and status filters for safe email outbox browsing.
/// </summary>
public sealed record EmailOutboxSearchRequest
{
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
/// <param name="Audit">Required audit context identifying the operator or calling workflow.</param>
public sealed record EmailOutboxOperationRequest(
    Guid Id,
    AuditContext Audit);

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
/// <param name="SuppressPublicFields">Whether recipient and <paramref name="Subject" /> metadata must be omitted because the row can contain live secrets or protected content.</param>
public sealed record EmailOutboxAdministrationOperationState(
    Guid Id,
    string? ToAddress,
    string? Subject,
    EmailOutboxStatus Status,
    bool SuppressPublicFields = false);

/// <summary>
/// Provider-facing email outbox projection used by safe administration mapping helpers.
/// </summary>
/// <param name="Id">The durable email outbox entry id.</param>
/// <param name="ToAddress">The stored recipient address.</param>
/// <param name="FromAddress">The stored sender address.</param>
/// <param name="ReplyToAddress">The stored reply-to address.</param>
/// <param name="CcAddress">The stored CC address list.</param>
/// <param name="BccAddress">The stored BCC address list.</param>
/// <param name="Subject">The stored message subject.</param>
/// <param name="TextBody">The stored text body.</param>
/// <param name="HtmlBody">The stored HTML body.</param>
/// <param name="Headers">The stored serialized headers, used only to derive safe flags.</param>
/// <param name="Metadata">The stored serialized metadata, used only to derive safe flags.</param>
/// <param name="Sensitivity">The persisted message sensitivity.</param>
/// <param name="BodyProtection">The persisted body protection marker.</param>
/// <param name="Status">The provider-derived outbox status.</param>
/// <param name="AttemptCount">The attempted delivery count.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastAttemptAt">The last attempt timestamp.</param>
/// <param name="FailedAt">The terminal failure timestamp.</param>
/// <param name="SentAt">The sent timestamp.</param>
/// <param name="DiscardedAt">The discarded timestamp.</param>
/// <param name="LockedBy">The dispatcher lock owner.</param>
/// <param name="LockedUntil">The dispatcher lock expiration timestamp.</param>
/// <param name="LastError">The stored failure detail.</param>
public sealed record EmailOutboxAdministrationProjection(
    Guid Id,
    string? ToAddress,
    string? FromAddress,
    string? ReplyToAddress,
    string? CcAddress,
    string? BccAddress,
    string? Subject,
    string? TextBody,
    string? HtmlBody,
    string? Headers,
    string? Metadata,
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
    string? LockedBy,
    DateTimeOffset? LockedUntil,
    string? LastError);

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

        ArgumentNullException.ThrowIfNull(request.Audit);
    }

    /// <summary>
    /// Creates a safe email outbox summary.
    /// </summary>
    /// <param name="record">Stored provider-neutral outbox row.</param>
    /// <returns>A summary that omits message bodies, protected payloads, headers, metadata, lock owners, and sensitive fields.</returns>
    public static EmailOutboxSummary CreateSummary(EmailOutboxAdministrationProjection record)
    {
        ArgumentNullException.ThrowIfNull(record);

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

    /// <summary>
    /// Creates a safe email outbox detail.
    /// </summary>
    /// <param name="record">Stored provider-neutral outbox row.</param>
    /// <returns>A detail projection that reports body presence without returning body, protected payload, header, metadata, or lock-owner values.</returns>
    public static EmailOutboxDetail CreateDetail(EmailOutboxAdministrationProjection record)
    {
        ArgumentNullException.ThrowIfNull(record);

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
            record.TextBody != null,
            record.HtmlBody != null,
            record.AttemptCount,
            record.CreatedAt,
            record.AvailableAt,
            record.LastAttemptAt,
            record.FailedAt,
            record.SentAt,
            record.DiscardedAt,
            CreateLastErrorSummary(record));
    }

    /// <summary>
    /// Creates a conservative error summary from stored failure details.
    /// </summary>
    /// <param name="record">Stored provider-neutral outbox row.</param>
    /// <returns>A single-line truncated failure summary, or a generic summary when message content may be sensitive.</returns>
    public static string? CreateLastErrorSummary(EmailOutboxAdministrationProjection record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.LastError is null)
        {
            return null;
        }

        if (IsSensitive(record))
        {
            return SensitiveFailureSummary;
        }

        var summary = record.LastError.Replace('\r', ' ').Replace('\n', ' ').Trim();
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

    /// <summary>
    /// Creates a safe operation result from stored outbox metadata and the supplied <paramref name="status" />.
    /// </summary>
    /// <param name="status">The operation status.</param>
    /// <param name="id">The outbox entry id.</param>
    /// <param name="toAddress">The stored recipient address.</param>
    /// <param name="subject">The stored subject.</param>
    /// <param name="outboxStatus">The stored outbox status.</param>
    /// <param name="suppressPublicFields">Whether recipient and subject metadata must be suppressed.</param>
    /// <returns>A mutation result that omits public metadata when the row may contain live secrets or protected content.</returns>
    public static EmailOutboxOperationResult CreateOperationResult(
        EmailOutboxOperationStatus status,
        Guid id,
        string? toAddress = null,
        string? subject = null,
        EmailOutboxStatus? outboxStatus = null,
        bool suppressPublicFields = false)
    {
        return new EmailOutboxOperationResult(
            status,
            id,
            suppressPublicFields ? null : NullIfUnsafeMultiline(toAddress),
            suppressPublicFields ? null : NullIfUnsafeMultiline(subject),
            outboxStatus);
    }

    /// <summary>
    /// Creates a safe operation result from stored outbox metadata and the supplied <paramref name="status" />.
    /// </summary>
    /// <param name="status">The operation status.</param>
    /// <param name="state">Stored safe state for the outbox entry.</param>
    /// <returns>A mutation result that omits recipient and subject metadata when the row may contain live secrets or protected content.</returns>
    public static EmailOutboxOperationResult CreateOperationResult(
        EmailOutboxOperationStatus status,
        EmailOutboxAdministrationOperationState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return CreateOperationResult(status, state.Id, state.ToAddress, state.Subject, state.Status, state.SuppressPublicFields);
    }

    /// <summary>
    /// Classifies a provider no-op after a conditional operation updated no rows.
    /// </summary>
    /// <param name="id">The requested outbox entry id.</param>
    /// <param name="state">The loaded safe state, or <see langword="null" /> when missing.</param>
    /// <returns>A stable not-found, already-discarded, or not-failed outcome.</returns>
    public static EmailOutboxOperationResult CreateNoOpResult(Guid id, EmailOutboxAdministrationOperationState? state)
    {
        if (state is null)
        {
            return CreateOperationResult(EmailOutboxOperationStatus.NotFound, id);
        }

        var status = state.Status == EmailOutboxStatus.Discarded
            ? EmailOutboxOperationStatus.AlreadyDiscarded
            : EmailOutboxOperationStatus.NotFailed;
        return CreateOperationResult(status, state.Id, state.ToAddress, state.Subject, state.Status, state.SuppressPublicFields);
    }

    /// <summary>
    /// Records an audit event for a successful manual email outbox mutation.
    /// </summary>
    /// <param name="sink">Audit sink that receives the security event.</param>
    /// <param name="timeProvider">Clock used for the audit timestamp.</param>
    /// <param name="eventType">Security event type describing the mutation.</param>
    /// <param name="request">Operation request containing the required audit context.</param>
    /// <param name="result">Safe operation result used to identify the mutated outbox entry.</param>
    /// <param name="cancellationToken">A token that can cancel audit emission.</param>
    /// <returns>A task representing audit emission.</returns>
    public static async Task RecordSuccessfulOperationAsync(
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
            request.Audit,
            new Dictionary<string, string> { ["email_outbox_id"] = result.Id.ToString("D") },
            cancellationToken).ConfigureAwait(false);
    }

    private static bool IsSensitive(EmailOutboxAdministrationProjection record)
    {
        return record.Sensitivity == EmailMessageSensitivity.ContainsLiveSecret ||
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
}
