using Ashlar.Identity.Models.Mfa;

namespace Ashlar.Testing;

/// <summary>Creates Ashlar-issued proof values for integration tests.</summary>
public static class FreshMfaVerificationProofFactory
{
    /// <summary>Creates a proof bound to the supplied user, session, lifetime, and purpose.</summary>
    /// <param name="userId">Proof owner.</param>
    /// <param name="tenantId">Proof tenant.</param>
    /// <param name="sessionId">Source session.</param>
    /// <param name="verifiedAt">Verification time.</param>
    /// <param name="expiresAt">Expiry time.</param>
    /// <param name="purpose">Required proof purpose.</param>
    /// <returns>The test proof.</returns>
    public static FreshMfaVerificationProof Create(Guid userId, Guid? tenantId, Guid sessionId,
        DateTimeOffset verifiedAt, DateTimeOffset expiresAt, string purpose) =>
        new(userId, tenantId, sessionId, verifiedAt, expiresAt, purpose);
}
