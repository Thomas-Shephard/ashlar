namespace Ashlar.Authorization.Models;

public sealed class AuthorizationGrantOptions
{
    public int MaxRoleLength { get; set; } = 128;
    public int MaxPermissionLength { get; set; } = 256;
    public int MaxScopeTypeLength { get; set; } = 128;
    public int MaxScopeIdLength { get; set; } = 256;
    public int MaxMetadataLength { get; set; } = 8192;

    public static bool Validate(AuthorizationGrantOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return options is { MaxRoleLength: > 0, MaxPermissionLength: > 0, MaxScopeTypeLength: > 0, MaxScopeIdLength: > 0, MaxMetadataLength: > 0 };
    }
}
