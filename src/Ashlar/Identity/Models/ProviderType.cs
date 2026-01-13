namespace Ashlar.Identity.Models;

public readonly record struct ProviderType
{
    private readonly string _value;
    public string Value => _value ?? string.Empty;

    private ProviderType(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        _value = value.ToUpperInvariant();
    }

    public static readonly ProviderType Local = new(nameof(Local));
    public static readonly ProviderType OAuth = new(nameof(OAuth));
    public static readonly ProviderType Oidc = new(nameof(Oidc));
    public static readonly ProviderType Saml2 = new(nameof(Saml2));
    public static readonly ProviderType Totp = new(nameof(Totp));
    public static readonly ProviderType Fido2 = new(nameof(Fido2));
    public static readonly ProviderType RecoveryCode = new(nameof(RecoveryCode));

    public override string ToString() => _value ?? string.Empty;

    public static implicit operator string(ProviderType type) => type.Value;
    public static implicit operator ProviderType(string value) => new(value);
}
