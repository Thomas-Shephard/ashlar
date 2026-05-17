namespace Ashlar.Identity.Models;

/// <summary>
/// Identifies the category of an authentication provider or stored credential.
/// </summary>
public readonly record struct ProviderType
{
    /// <summary>
    /// Gets the provider type value used when a provider type was not initialized.
    /// </summary>
    public const string UnknownValue = "UNKNOWN";

    /// <summary>
    /// Gets the normalized provider type value.
    /// </summary>
    public string Value => field ?? throw new InvalidOperationException("ProviderType must be initialized with a non-empty value.");

    /// <summary>
    /// Gets the provider type value, or a stable sentinel when this instance was not initialized.
    /// </summary>
    public string ValueOrUnknown => this == default ? UnknownValue : Value;

    private ProviderType(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value.ToUpperInvariant();
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
    /// Returns the normalized provider type value.
    /// </summary>
    /// <returns>The normalized provider type value.</returns>
    public override string ToString() => Value;

    /// <summary>
    /// Converts a provider type to its normalized string value.
    /// </summary>
    /// <param name="type">The provider type to convert.</param>
    /// <returns>The normalized provider type value.</returns>
    public static implicit operator string(ProviderType type) => type.Value;
    /// <summary>
    /// Creates a provider type from a non-empty string.
    /// </summary>
    /// <param name="value">The provider type value.</param>
    /// <returns>The provider type.</returns>
    public static implicit operator ProviderType(string value) => new(value);
}
