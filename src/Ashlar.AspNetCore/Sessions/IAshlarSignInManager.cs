using Ashlar.Identity.Models;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Sessions;

public interface IAshlarSignInManager
{
    Task<AuthenticationSession> SignInAsync(
        HttpContext httpContext,
        Guid userId,
        CreateAuthenticationSessionRequest? request = null,
        CancellationToken cancellationToken = default);

    Task SignOutAsync(
        HttpContext httpContext,
        string? reason = null,
        CancellationToken cancellationToken = default);
}
