namespace Ashlar.Operational;

/// <summary>
/// Provides ashlar cleanup options behavior.
/// </summary>
public sealed class AshlarCleanupOptions
{
    /// <summary>
    /// Maximum rows to delete from one cleanup category in a single batch.
    /// </summary>
    public int BatchSize { get; set; } = 500;

    /// <summary>
    /// Maximum cleanup batches to run during one explicit or hosted cleanup call.
    /// </summary>
    public int MaxBatchesPerRun { get; set; } = 10;

    /// <summary>
    /// Delay between hosted cleanup runs.
    /// </summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Retention period after session expiration. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes expired rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveExpiredSessionsAfter { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Retention period after session revocation. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes revoked rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveRevokedSessionsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after credential expiration. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes expired rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveExpiredCredentialsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after credential revocation. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes revoked rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveRevokedCredentialsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after authorization grant expiration. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes expired rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveExpiredAuthorizationGrantsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after authorization grant revocation. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes revoked rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveRevokedAuthorizationGrantsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after invitation expiration. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes expired rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveExpiredInvitationsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after invitation acceptance. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes accepted rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveAcceptedInvitationsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after invitation revocation. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes revoked rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveRevokedInvitationsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Retention period after MFA handshake expiration. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes expired rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveExpiredHandshakesAfter { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Retention period after MFA handshake completion. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes completed rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveCompletedHandshakesAfter { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Retention period after MFA handshake revocation. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes revoked rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveRevokedHandshakesAfter { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Retention period after rate-limit row expiration. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes expired rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveExpiredRateLimitsAfter { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Retention period after audit events occur. <see langword="null" /> disables audit-event cleanup; <see cref="TimeSpan.Zero"/> deletes all audit events on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveAuditEventsAfter { get; set; }

    /// <summary>
    /// Retention period after email messages are sent. <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes sent rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveSentEmailsAfter { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Retention period after email messages are marked as failed (all attempts exhausted). <see langword="null" /> disables cleanup; <see cref="TimeSpan.Zero"/> deletes failed rows on the next cleanup run.
    /// </summary>
    public TimeSpan? RemoveFailedEmailsAfter { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Performs the validate operation and returns the result.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns>The operation result.</returns>
    public static bool Validate(AshlarCleanupOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.BatchSize <= 0 || options.MaxBatchesPerRun <= 0 || options.CleanupInterval <= TimeSpan.Zero)
        {
            return false;
        }

        return IsValid(options.RemoveExpiredSessionsAfter)
            && IsValid(options.RemoveRevokedSessionsAfter)
            && IsValid(options.RemoveExpiredCredentialsAfter)
            && IsValid(options.RemoveRevokedCredentialsAfter)
            && IsValid(options.RemoveExpiredAuthorizationGrantsAfter)
            && IsValid(options.RemoveRevokedAuthorizationGrantsAfter)
            && IsValid(options.RemoveExpiredInvitationsAfter)
            && IsValid(options.RemoveAcceptedInvitationsAfter)
            && IsValid(options.RemoveRevokedInvitationsAfter)
            && IsValid(options.RemoveExpiredHandshakesAfter)
            && IsValid(options.RemoveCompletedHandshakesAfter)
            && IsValid(options.RemoveRevokedHandshakesAfter)
            && IsValid(options.RemoveExpiredRateLimitsAfter)
            && IsValid(options.RemoveAuditEventsAfter)
            && IsValid(options.RemoveSentEmailsAfter)
            && IsValid(options.RemoveFailedEmailsAfter);
    }

    private static bool IsValid(TimeSpan? value) => value == null || value.Value >= TimeSpan.Zero;
}
