namespace Ashlar.Authorization.Models;

/// <summary>
/// Configures validation limits for authorization grant values.
/// </summary>
public sealed class AuthorizationGrantOptions
{
    /// <summary>
    /// Maximum allowed length for role names.
    /// </summary>
    public int MaxRoleLength { get; set; } = 128;
    /// <summary>
    /// Maximum allowed length for permission names.
    /// </summary>
    public int MaxPermissionLength { get; set; } = 256;
    /// <summary>
    /// Maximum allowed length for scope type names.
    /// </summary>
    public int MaxScopeTypeLength { get; set; } = 128;
    /// <summary>
    /// Maximum allowed length for scope identifiers.
    /// </summary>
    public int MaxScopeIdLength { get; set; } = 256;
    /// <summary>
    /// Maximum allowed length for provider-neutral grant metadata.
    /// </summary>
    public int MaxMetadataLength { get; set; } = 8192;

    /// <summary>
    /// Validates authorization grant options.
    /// </summary>
    /// <param name="options">The options instance to validate.</param>
    /// <returns><see langword="true" /> when all configured limits are positive.</returns>
    public static bool Validate(AuthorizationGrantOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options is { MaxRoleLength: > 0, MaxPermissionLength: > 0, MaxScopeTypeLength: > 0, MaxScopeIdLength: > 0, MaxMetadataLength: > 0 };
    }
}
