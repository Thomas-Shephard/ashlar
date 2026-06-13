namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Identifies an authentication provider by provider type and provider name.
/// </summary>
public readonly record struct AuthenticationProviderKey
{
    /// <summary>
    /// Provider category, such as local, email-code, passkey, or external.
    /// </summary>
    public ProviderType Type { get; }
    /// <summary>
    /// Provider name within its provider type.
    /// </summary>
    public string Name => field ?? string.Empty;

    /// <summary>
    /// Serialized provider type, or a stable sentinel when this key was not initialized.
    /// </summary>
    public string TypeValueOrDefault => Type.ValueOrUnknown;

    /// <summary>
    /// Whether this provider key has both a provider type and provider name.
    /// </summary>
    public bool IsInitialized => Type != default && !string.IsNullOrWhiteSpace(Name);

    /// <summary>
    /// Gets the serialized provider type for an optional provider key, or <see langword="null" /> when no provider key was supplied.
    /// </summary>
    /// <param name="provider">Optional provider key to inspect.</param>
    /// <returns>The serialized provider type, the unknown sentinel, or <see langword="null" />.</returns>
    public static string? GetTypeValueOrDefault(AuthenticationProviderKey? provider)
    {
        return provider.HasValue ? provider.Value.TypeValueOrDefault : null;
    }

    /// <summary>
    /// Throws when an authentication provider key has not been fully initialized.
    /// </summary>
    /// <param name="provider">Provider key to validate.</param>
    /// <param name="parameterName">The parameter name to include in the exception.</param>
    /// <exception cref="ArgumentException">Thrown when the provider key is uninitialized.</exception>
    public static void ThrowIfUninitialized(AuthenticationProviderKey provider, string parameterName)
    {
        if (!provider.IsInitialized)
        {
            throw new ArgumentException("Provider key must be fully initialized with a type and name.", parameterName);
        }
    }

    /// <summary>
    /// Initializes a provider key from a type and provider name.
    /// </summary>
    /// <param name="type">Provider category for this key.</param>
    /// <param name="name">Provider name within the category.</param>
    public AuthenticationProviderKey(ProviderType type, string name)
    {
        if (type == default)
        {
            throw new ArgumentException("Provider type must be initialized.", nameof(type));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Type = type;
        Name = name.Trim();
    }

    /// <summary>
    /// Built-in local password provider key.
    /// </summary>
    public static AuthenticationProviderKey Local { get; } = new(ProviderType.Local, ProviderType.Local.Value);
    /// <summary>
    /// Built-in email-code provider key.
    /// </summary>
    public static AuthenticationProviderKey EmailCode { get; } = new(ProviderType.EmailCode, ProviderType.EmailCode.Value);
    /// <summary>
    /// Built-in magic-link provider key.
    /// </summary>
    public static AuthenticationProviderKey MagicLink { get; } = new(ProviderType.MagicLink, ProviderType.MagicLink.Value);
    /// <summary>
    /// Built-in passkey provider key.
    /// </summary>
    public static AuthenticationProviderKey Passkey { get; } = new(ProviderType.Passkey, ProviderType.Passkey.Value);

    /// <summary>
    /// Compares provider keys using case-insensitive provider names.
    /// </summary>
    /// <param name="other">Provider key to compare with this key.</param>
    /// <returns><see langword="true" /> when both keys identify the same provider.</returns>
    public bool Equals(AuthenticationProviderKey other)
    {
        return Type == other.Type && StringComparer.OrdinalIgnoreCase.Equals(Name, other.Name);
    }

    /// <summary>
    /// Returns a hash code compatible with case-insensitive provider name comparison.
    /// </summary>
    /// <returns>A hash code for this provider key.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Type, StringComparer.OrdinalIgnoreCase.GetHashCode(Name));
    }

    /// <summary>
    /// Formats the provider key as <c>type:name</c>.
    /// </summary>
    /// <returns>A provider key string suitable for diagnostics, but not for authorization decisions.</returns>
    public override string ToString()
    {
        return Type == default
            ? "<uninitialized provider>"
            : $"{Type.Value}:{Name}";
    }
}
