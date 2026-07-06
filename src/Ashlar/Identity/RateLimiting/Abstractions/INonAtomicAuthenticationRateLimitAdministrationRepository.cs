namespace Ashlar.Identity.RateLimiting.Abstractions;

/// <summary>
/// Marks an authentication rate-limit administration repository whose reset mutations cannot share Ashlar transactions.
/// </summary>
/// <remarks>
/// Services use this marker to fail closed before non-transactional resets when durable audit storage is configured.
/// </remarks>
public interface INonAtomicAuthenticationRateLimitAdministrationRepository;
