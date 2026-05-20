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

    /// <summary>
    /// The Ashlar tenant scope associated with the current authentication session.
    /// </summary>
    public const string TenantId = "ashlar:tenant_id";

    /// <summary>
    /// The time the user authenticated for the current session.
    /// </summary>
    public const string AuthenticatedAt = "ashlar:auth_time";

    /// <summary>
    /// The primary provider type used to create the current session.
    /// </summary>
    public const string PrimaryProviderType = "ashlar:primary_provider_type";

    /// <summary>
    /// The primary provider name used to create the current session.
    /// </summary>
    public const string PrimaryProviderName = "ashlar:primary_provider_name";

    /// <summary>
    /// The time additional verification was completed for the current session.
    /// </summary>
    public const string AdditionalVerificationAt = "ashlar:additional_verification_time";

    /// <summary>
    /// The additional verification provider type used for the current session.
    /// </summary>
    public const string AdditionalVerificationProviderType = "ashlar:additional_verification_provider_type";

    /// <summary>
    /// The additional verification provider name used for the current session.
    /// </summary>
    public const string AdditionalVerificationProviderName = "ashlar:additional_verification_provider_name";

    /// <summary>
    /// The additional verification factor used for the current session.
    /// </summary>
    public const string AdditionalVerificationFactor = "ashlar:additional_verification_factor";
}


