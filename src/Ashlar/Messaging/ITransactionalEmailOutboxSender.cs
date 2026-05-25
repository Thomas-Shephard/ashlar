namespace Ashlar.Messaging;

/// <summary>
/// Marks an email sender as a durable outbox that participates in the active Ashlar transaction.
/// </summary>
public interface ITransactionalEmailOutboxSender : IEmailSender;
