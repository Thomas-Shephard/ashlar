namespace Ashlar.Identity.Abstractions;

public interface ISessionTicketSerializer
{
    /// <summary>
    /// Serializes the handshake into an encrypted session ticket.
    /// </summary>
    /// <param name="handshake">The handshake to serialize.</param>
    /// <returns>An encrypted string representing the session ticket.</returns>
    string Serialize(IAuthenticationHandshake handshake);

    /// <summary>
    /// Deserializes an encrypted session ticket into a handshake.
    /// </summary>
    /// <param name="sessionTicket">The encrypted session ticket.</param>
    /// <returns>The deserialized handshake, or null if the ticket is invalid or expired.</returns>
    IAuthenticationHandshake? Deserialize(string sessionTicket);
}
