namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Identifies the category of an authentication provider or stored credential.
/// </summary>
public readonly record struct ProviderType
{
    private readonly string? _value;

    /// <summary>
    /// Storage fallback value used when a provider type is unavailable for persisted records.
    /// </summary>
    public const string StorageFallbackValue = "UNKNOWN";

    /// <summary>
    /// Gets whether this provider type is the storage fallback, as opposed to a configured provider type.
    /// </summary>
    public bool IsStorageFallback => _value is null || string.Equals(_value, StorageFallbackValue, StringComparison.Ordinal);

    /// <summary>
    /// Gets the normalized provider type string.
    /// </summary>
    public string Value => _value ?? throw new InvalidOperationException("ProviderType must be initialized with a non-empty value.");

    /// <summary>
    /// Gets the storage-safe provider type string for persisted diagnostics.
    /// </summary>
    public string StorageValue => IsStorageFallback ? StorageFallbackValue : Value;

    private ProviderType(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        _value = value.ToUpperInvariant();
    }

    /// <summary>
    /// Local interactive credentials such as passwords.
    /// </summary>
    public static readonly ProviderType Local = new(nameof(Local));
    /// <summary>
    /// Internal system-issued credentials.
    /// </summary>
    public static readonly ProviderType Internal = new(nameof(Internal));
    /// <summary>
    /// MFA credentials.
    /// </summary>
    public static readonly ProviderType Mfa = new(nameof(Mfa));
    /// <summary>
    /// Passwordless one-time email code credentials.
    /// </summary>
    public static readonly ProviderType EmailCode = new(nameof(EmailCode));
    /// <summary>
    /// Passwordless magic-link credentials.
    /// </summary>
    public static readonly ProviderType MagicLink = new(nameof(MagicLink));
    /// <summary>
    /// Recovery code credentials.
    /// </summary>
    public static readonly ProviderType RecoveryCode = new(nameof(RecoveryCode));
    /// <summary>
    /// WebAuthn/FIDO2 passkey credentials.
    /// </summary>
    public static readonly ProviderType Passkey = new(nameof(Passkey));
    /// <summary>
    /// OAuth credentials.
    /// </summary>
    public static readonly ProviderType OAuth = new(nameof(OAuth));
    /// <summary>
    /// OpenID Connect credentials.
    /// </summary>
    public static readonly ProviderType Oidc = new(nameof(Oidc));
    /// <summary>
    /// SAML 2.0 credentials.
    /// </summary>
    public static readonly ProviderType Saml2 = new(nameof(Saml2));

    /// <summary>
    /// Returns the normalized provider type string.
    /// </summary>
    /// <returns>Normalized provider type string.</returns>
    public override string ToString() => Value;

    /// <summary>
    /// Converts a provider type to its normalized string value.
    /// </summary>
    /// <param name="type">The provider type to convert.</param>
    /// <returns>Normalized provider type string.</returns>
    public static implicit operator string(ProviderType type) => type.Value;
    /// <summary>
    /// Creates a provider type from a non-empty string.
    /// </summary>
    /// <param name="value">Non-empty provider type string.</param>
    /// <returns>The provider type.</returns>
    public static implicit operator ProviderType(string value) => new(value);
}
