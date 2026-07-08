namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Low-level authentication pipeline used by orchestrators and advanced integrations to verify primary credentials through a configured provider.
/// </summary>
public interface IAuthenticationPipeline
{
    /// <summary>
    /// Performs primary sign-in authentication and returns the result.
    /// </summary>
    /// <param name="context">Request, tenant, client, and audit context supplied by the host application.</param>
    /// <param name="assertion">Primary credential assertion to verify. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="cancellationToken">A token that can cancel authentication.</param>
    /// <returns>The provider authentication response. This does not by itself issue an application session.</returns>
    Task<AuthenticationResponse> LoginAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Low-level authentication pipeline used by orchestrators and advanced integrations to verify secondary factors through a configured provider.
/// </summary>
public interface IAuthenticationFactorPipeline
{
    /// <summary>
    /// Verifies a secondary authentication factor without applying primary sign-in throttles.
    /// </summary>
    /// <param name="context">Request, tenant, client, and audit context supplied by the host application.</param>
    /// <param name="assertion">Secondary factor assertion to verify. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="cancellationToken">A token that can cancel factor verification.</param>
    /// <returns>The provider authentication response for the factor attempt. This does not by itself complete MFA, mark step-up verification, or issue or continue an application session.</returns>
    Task<AuthenticationResponse> VerifyFactorAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}
