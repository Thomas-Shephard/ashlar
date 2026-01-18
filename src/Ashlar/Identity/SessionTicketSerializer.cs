using System.Text.Json;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;

namespace Ashlar.Identity;

public sealed class SessionTicketSerializer(ISecretProtector secretProtector, IdentityServiceOptions? options = null) : ISessionTicketSerializer
{
    private readonly ISecretProtector _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    private readonly IdentityServiceOptions _options = options ?? new IdentityServiceOptions();

    public string Serialize(IAuthenticationHandshake handshake)
    {
        ArgumentNullException.ThrowIfNull(handshake);

        var dto = new SessionTicketDto
        {
            UserId = handshake.UserId,
            VerifiedFactors = handshake.VerifiedFactors.ToList(),
            TenantId = handshake.TenantId,
            ExpiresAt = DateTimeOffset.UtcNow.Add(_options.HandshakeExpiry)
        };

        var json = JsonSerializer.Serialize(dto);
        return _secretProtector.Protect(json);
    }

    public IAuthenticationHandshake? Deserialize(string sessionTicket)
    {
        if (string.IsNullOrWhiteSpace(sessionTicket))
        {
            return null;
        }

        try
        {
            var json = _secretProtector.Unprotect(sessionTicket);
            var dto = JsonSerializer.Deserialize<SessionTicketDto>(json);

            if (dto == null || dto.ExpiresAt < DateTimeOffset.UtcNow)
            {
                return null;
            }

            return new AuthenticationHandshake
            {
                UserId = dto.UserId,
                VerifiedFactors = dto.VerifiedFactors,
                TenantId = dto.TenantId,
                SessionTicket = sessionTicket
            };
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or JsonException)
        {
            return null;
        }
    }

    private sealed class SessionTicketDto
    {
        public Guid UserId { get; init; }
        public List<ProviderType> VerifiedFactors { get; init; } = [];
        public Guid? TenantId { get; init; }
        public DateTimeOffset ExpiresAt { get; init; }
    }
}
