namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Represents the struct data model.
/// </summary>
public readonly record struct AuthenticationProviderKey
{
    /// <summary>
    /// Gets or sets the type value.
    /// </summary>
    public ProviderType Type { get; }
    /// <summary>
    /// Gets or sets the name value.
    /// </summary>
    public string Name => field ?? string.Empty;

    /// <summary>
    /// Gets the provider type value, or a stable sentinel when this key's provider type was not initialized.
    /// </summary>
    public string TypeValueOrUnknown => Type.ValueOrUnknown;

    /// <summary>
    /// Gets the provider type value for an optional provider key, or <see langword="null" /> when no provider key was supplied.
    /// </summary>
    /// <param name="provider">The provider key value.</param>
    /// <returns>The provider type value, the unknown sentinel, or <see langword="null" />.</returns>
    public static string? GetTypeValueOrNull(AuthenticationProviderKey? provider)
    {
        return provider.HasValue ? provider.Value.TypeValueOrUnknown : null;
    }

    /// <summary>
    /// Initializes a new instance of the authentication provider key class.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <param name="name">The name value.</param>
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
    /// Executes the new operation.
    /// </summary>
    public static AuthenticationProviderKey Local { get; } = new(ProviderType.Local, ProviderType.Local.Value);
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    public static AuthenticationProviderKey EmailCode { get; } = new(ProviderType.EmailCode, ProviderType.EmailCode.Value);
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    public static AuthenticationProviderKey MagicLink { get; } = new(ProviderType.MagicLink, ProviderType.MagicLink.Value);
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    public static AuthenticationProviderKey Passkey { get; } = new(ProviderType.Passkey, ProviderType.Passkey.Value);

    /// <summary>
    /// Performs the equals operation and returns the result.
    /// </summary>
    /// <param name="other">The other value.</param>
    /// <returns>The operation result.</returns>
    public bool Equals(AuthenticationProviderKey other)
    {
        return Type == other.Type && StringComparer.OrdinalIgnoreCase.Equals(Name, other.Name);
    }

    /// <summary>
    /// Performs the get hash code operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Type, StringComparer.OrdinalIgnoreCase.GetHashCode(Name));
    }

    /// <summary>
    /// Performs the to string operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public override string ToString()
    {
        return Type == default
            ? "<uninitialized provider>"
            : $"{Type.Value}:{Name}";
    }
}
