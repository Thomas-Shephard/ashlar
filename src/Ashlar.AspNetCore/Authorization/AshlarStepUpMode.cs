namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Describes how an Ashlar step-up authorization requirement is applied.
/// </summary>
public enum AshlarStepUpMode
{
    /// <summary>
    /// Always requires fresh additional verification.
    /// </summary>
    Required = 0,

    /// <summary>
    /// Requires fresh additional verification only when the account has a usable eligible factor.
    /// </summary>
    IfAvailable = 1
}
