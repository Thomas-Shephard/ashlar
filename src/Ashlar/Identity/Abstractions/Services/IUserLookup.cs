namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Read-only user lookup capability supplied to authentication providers.</summary>
public interface IUserLookup
{
    /// <summary>Finds a user by normalized email within a tenant boundary.</summary>
    /// <param name="email">Email address to find.</param>
    /// <param name="tenantId">Tenant boundary, or <see langword="null" /> for a tenantless user.</param>
    /// <param name="cancellationToken">Token that can cancel the lookup.</param>
    /// <returns>The matching user, or <see langword="null" />.</returns>
    Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>Finds a user by stable identifier.</summary>
    /// <param name="userId">User identifier.</param>
    /// <param name="cancellationToken">Token that can cancel the lookup.</param>
    /// <returns>The matching user, or <see langword="null" />.</returns>
    Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>Finds the user linked to a provider credential key.</summary>
    /// <param name="type">Provider category.</param>
    /// <param name="providerName">Provider name within its category.</param>
    /// <param name="providerKey">Provider credential key.</param>
    /// <param name="cancellationToken">Token that can cancel the lookup.</param>
    /// <returns>The linked user, or <see langword="null" />.</returns>
    Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);
}
