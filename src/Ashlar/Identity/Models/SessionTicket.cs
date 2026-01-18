namespace Ashlar.Identity.Models;

/// <summary>
/// Represents an opaque session ticket used for stateful multi-factor authentication.
/// </summary>
/// <param name="Value">The encrypted ticket value.</param>
public sealed record SessionTicket(string Value)
{
    public override string ToString() => "[Redacted]";
}
