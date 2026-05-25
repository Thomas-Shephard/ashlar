using Ashlar.Messaging;

namespace Ashlar.Identity.Features.Email;

internal static class TransactionalEmailDelivery
{
    public static async Task SendOrRegisterPostCommitAsync(
        IEmailSender sender,
        IAshlarTransaction transaction,
        EmailMessage message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sender);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(message);

        if (sender is ITransactionalEmailOutboxSender)
        {
            await sender.SendAsync(message, cancellationToken);
            return;
        }

        transaction.OnCommitted(ct => sender.SendAsync(message, ct));
    }

    public static bool IsTransactionalDurableOutbox(IEmailSender sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        return sender is ITransactionalEmailOutboxSender;
    }
}
