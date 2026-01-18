using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ashlar.Identity.Models;

[JsonConverter(typeof(ProviderTypeJsonConverter))]
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

    public override string ToString() => _value ?? string.Empty;

    public static implicit operator string(ProviderType type) => type.Value;
    public static implicit operator ProviderType(string value) => new(value);

    private sealed class ProviderTypeJsonConverter : JsonConverter<ProviderType>
    {
        public override ProviderType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var value = reader.GetString();
            return !string.IsNullOrWhiteSpace(value) ? new ProviderType(value) : default;
        }

        public override void Write(Utf8JsonWriter writer, ProviderType value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.Value);
        }
    }
}
