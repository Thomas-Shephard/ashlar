namespace Ashlar.Identity.Models;

public readonly record struct AuthenticationProviderKey
{
    public ProviderType Type { get; }
    public string Name => field ?? string.Empty;

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

    public static AuthenticationProviderKey Local { get; } = new(ProviderType.Local, ProviderType.Local.Value);
    public static AuthenticationProviderKey EmailCode { get; } = new(ProviderType.EmailCode, ProviderType.EmailCode.Value);
    public static AuthenticationProviderKey MagicLink { get; } = new(ProviderType.MagicLink, ProviderType.MagicLink.Value);

    public bool Equals(AuthenticationProviderKey other)
    {
        return Type == other.Type && StringComparer.OrdinalIgnoreCase.Equals(Name, other.Name);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Type, StringComparer.OrdinalIgnoreCase.GetHashCode(Name));
    }

    public override string ToString()
    {
        return Type == default 
            ? "<uninitialized provider>" 
            : $"{Type.Value}:{Name}";
    }
}
