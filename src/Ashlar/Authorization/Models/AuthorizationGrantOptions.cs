namespace Ashlar.Authorization.Models;

/// <summary>
/// Provides authorization grant options behavior.
/// </summary>
public sealed class AuthorizationGrantOptions
{
    /// <summary>
    /// Gets or sets the max role length value.
    /// </summary>
    public int MaxRoleLength { get; set; } = 128;
    /// <summary>
    /// Gets or sets the max permission length value.
    /// </summary>
    public int MaxPermissionLength { get; set; } = 256;
    /// <summary>
    /// Gets or sets the max scope type length value.
    /// </summary>
    public int MaxScopeTypeLength { get; set; } = 128;
    /// <summary>
    /// Gets or sets the max scope id length value.
    /// </summary>
    public int MaxScopeIdLength { get; set; } = 256;
    /// <summary>
    /// Gets or sets the max metadata length value.
    /// </summary>
    public int MaxMetadataLength { get; set; } = 8192;

    /// <summary>
    /// Performs the validate operation and returns the result.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns>The operation result.</returns>
    public static bool Validate(AuthorizationGrantOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options is { MaxRoleLength: > 0, MaxPermissionLength: > 0, MaxScopeTypeLength: > 0, MaxScopeIdLength: > 0, MaxMetadataLength: > 0 };
    }
}
