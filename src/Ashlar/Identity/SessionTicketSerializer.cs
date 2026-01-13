using System.Text.Json;
using Ashlar.Identity.Abstractions;
using Ashlar.Security.Encryption;

namespace Ashlar.Identity;

public sealed class SessionTicketSerializer
{
    private readonly ISecretProtector _secretProtector;

    public SessionTicketSerializer(ISecretProtector secretProtector)
    {
        _secretProtector = secretProtector;
    }

    public string Serialize(Guid userId, IEnumerable<string> verifiedFactors, Guid? tenantId = null)
    {
        var dto = new TicketDto
        {
            UserId = userId,
            VerifiedFactors = verifiedFactors.ToList(),
            TenantId = tenantId,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(dto);
        return _secretProtector.Protect(json);
    }

    public IAuthenticationHandshake? Deserialize(string sessionTicket)
    {
        try
        {
            var json = _secretProtector.Unprotect(sessionTicket);
            var dto = JsonSerializer.Deserialize<TicketDto>(json);

            var now = DateTimeOffset.UtcNow;
            if (dto == null || 
                dto.CreatedAt > now.AddMinutes(1) || // Clock skew protection
                dto.CreatedAt < now.AddMinutes(-15)) // 15 minute expiry
            {
                return null;
            }

            return new AuthenticationHandshake(sessionTicket, dto.UserId, dto.VerifiedFactors, dto.TenantId);
        }
        catch
        {
            return null;
        }
    }

    private sealed class TicketDto
    {
        public Guid UserId { get; set; }
        public List<string> VerifiedFactors { get; set; } = new();
        public Guid? TenantId { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }
}
