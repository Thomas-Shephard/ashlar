namespace Ashlar.AspNetCore.Authentication;

/// <summary>
/// Claim type constants emitted by Ashlar's ASP.NET Core authentication handler.
/// </summary>
public static class AshlarClaimTypes
{
    /// <summary>
    /// The durable Ashlar authentication session identifier.
    /// </summary>
    public const string SessionId = "ashlar:session_id";
}
