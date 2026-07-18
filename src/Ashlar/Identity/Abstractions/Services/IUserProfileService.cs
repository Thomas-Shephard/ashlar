using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Provides application-safe access to the current user's display profile.</summary>
public interface IUserProfileService
{
    /// <summary>Gets the current user's display profile.</summary>
    /// <param name="session">The Ashlar-issued validated session.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The display profile, or a failure when the session or user is unavailable.</returns>
    Task<Result<UserProfile>> GetAsync(ValidatedAuthenticationSession session, CancellationToken cancellationToken = default);

    /// <summary>Updates the current user's display name.</summary>
    /// <param name="request">The validated current-session update request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The updated display profile, or a failure result.</returns>
    Task<Result<UserProfile>> UpdateNameAsync(UpdateCurrentUserProfileRequest request, CancellationToken cancellationToken = default);
}

/// <summary>Validated current-user capability for a self-service profile update.</summary>
/// <param name="Session">The Ashlar-issued validated session.</param>
/// <param name="Name">The new display name.</param>
/// <param name="Audit">Audit context whose actor must own <paramref name="Session" />.</param>
public sealed record UpdateCurrentUserProfileRequest(ValidatedAuthenticationSession Session, string? Name, AuditContext Audit);

/// <summary>Display-safe user profile fields.</summary>
/// <param name="UserId">The user identifier.</param>
/// <param name="DisplayEmail">The display email address.</param>
/// <param name="Name">The display name.</param>
public sealed record UserProfile(Guid UserId, string DisplayEmail, string? Name);
