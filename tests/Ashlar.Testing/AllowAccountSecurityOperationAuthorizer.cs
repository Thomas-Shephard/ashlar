using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.AccountSecurity;

namespace Ashlar.Testing;

/// <summary>Test host authorizer that permits every account-security operation.</summary>
public sealed class AllowAccountSecurityOperationAuthorizer : IAccountSecurityOperationAuthorizer
{
    /// <inheritdoc />
    public ValueTask<bool> AuthorizeAsync(
        AccountSecurityAuthorizationContext context,
        CancellationToken cancellationToken = default) => ValueTask.FromResult(true);
}
