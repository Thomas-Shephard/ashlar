namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Represents an authentication provider identity exactly as it is stored for diagnostics and audit records.
/// </summary>
public readonly record struct PersistedAuthenticationProviderKey
{
    /// <summary>
    /// Provider type storage value, or <see langword="null" /> when no provider was persisted.
    /// </summary>
    public string? ProviderTypeValue { get; }

    /// <summary>
    /// Provider name storage value, or <see langword="null" /> when no provider was persisted.
    /// </summary>
    public string? ProviderName { get; }

    /// <summary>
    /// Classifies the persisted provider value shape without requiring callers to parse storage strings.
    /// </summary>
    public PersistedAuthenticationProviderKind Kind { get; }

    /// <summary>
    /// Initializes persisted provider values.
    /// </summary>
    /// <param name="providerTypeValue">Provider type storage value, or <see langword="null" /> when no provider was persisted.</param>
    /// <param name="providerName">Provider name storage value, or <see langword="null" /> when no provider was persisted.</param>
    public PersistedAuthenticationProviderKey(string? providerTypeValue, string? providerName)
    {
        ProviderTypeValue = providerTypeValue;
        ProviderName = providerName;
        Kind = GetKind(providerTypeValue, providerName);
    }

    /// <summary>
    /// Creates persisted provider values from an optional authentication provider key.
    /// </summary>
    /// <param name="provider">Provider key to persist, or <see langword="null" /> when no provider is associated with the record.</param>
    /// <returns>Storage values for the provider.</returns>
    public static PersistedAuthenticationProviderKey FromProvider(AuthenticationProviderKey? provider)
    {
        return provider.HasValue
            ? new PersistedAuthenticationProviderKey(provider.Value.StorageTypeValue, provider.Value.Name)
            : default;
    }

    /// <summary>
    /// Converts persisted provider values back to an optional provider key.
    /// </summary>
    /// <returns>The provider key, the default fallback key, or <see langword="null" /> when no usable provider was persisted.</returns>
    public AuthenticationProviderKey? ToProviderKey()
    {
        return Kind switch
        {
            PersistedAuthenticationProviderKind.Configured => new AuthenticationProviderKey((ProviderType)ProviderTypeValue!, ProviderName!),
            PersistedAuthenticationProviderKind.StorageFallback => default(AuthenticationProviderKey),
            _ => null
        };
    }

    private static PersistedAuthenticationProviderKind GetKind(string? providerTypeValue, string? providerName)
    {
        if (string.IsNullOrWhiteSpace(providerTypeValue))
        {
            return PersistedAuthenticationProviderKind.None;
        }

        if (string.Equals(providerTypeValue, ProviderType.StorageFallbackValue, StringComparison.Ordinal))
        {
            return PersistedAuthenticationProviderKind.StorageFallback;
        }

        return string.IsNullOrWhiteSpace(providerName)
            ? PersistedAuthenticationProviderKind.Incomplete
            : PersistedAuthenticationProviderKind.Configured;
    }
}
