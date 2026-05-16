namespace Ashlar.Identity.Models;

/// <summary>
/// Represents the struct data model.
/// </summary>
public readonly record struct ProviderType
{
    /// <summary>
    /// Gets the provider type value used when a provider type was not initialized.
    /// </summary>
    public const string UnknownValue = "UNKNOWN";

    /// <summary>
    /// Executes the invalid operation exception operation.
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
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType Local = new(nameof(Local));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType Internal = new(nameof(Internal));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType Mfa = new(nameof(Mfa));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType EmailCode = new(nameof(EmailCode));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType MagicLink = new(nameof(MagicLink));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType RecoveryCode = new(nameof(RecoveryCode));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType OAuth = new(nameof(OAuth));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType Oidc = new(nameof(Oidc));
    /// <summary>
    /// Performs the new operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static readonly ProviderType Saml2 = new(nameof(Saml2));

    /// <summary>
    /// Executes the to string operation.
    /// </summary>
    /// <returns>The operation result.</returns>
    public override string ToString() => Value;

    /// <summary>
    /// Executes the string operation.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <returns>The operation result.</returns>
    public static implicit operator string(ProviderType type) => type.Value;
    /// <summary>
    /// Executes the provider type operation.
    /// </summary>
    /// <param name="value">The provider type value.</param>
    /// <returns>The operation result.</returns>
    public static implicit operator ProviderType(string value) => new(value);
}
