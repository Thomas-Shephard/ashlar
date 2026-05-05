namespace Ashlar.Identity.Models;

public readonly record struct ProviderType
{
    public string Value => field ?? throw new InvalidOperationException("ProviderType must be initialized with a non-empty value.");

    private ProviderType(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value.ToUpperInvariant();
    }

    public static readonly ProviderType Local = new(nameof(Local));
    public static readonly ProviderType EmailCode = new(nameof(EmailCode));
    public static readonly ProviderType MagicLink = new(nameof(MagicLink));
    public static readonly ProviderType RecoveryCode = new(nameof(RecoveryCode));
    public static readonly ProviderType OAuth = new(nameof(OAuth));
    public static readonly ProviderType Oidc = new(nameof(Oidc));
    public static readonly ProviderType Saml2 = new(nameof(Saml2));

    public override string ToString() => Value;

    public static implicit operator string(ProviderType type) => type.Value;
    public static implicit operator ProviderType(string value) => new(value);
}
