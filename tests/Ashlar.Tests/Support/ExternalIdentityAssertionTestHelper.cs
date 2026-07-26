using Ashlar.Identity.Providers.External;

namespace Ashlar.Tests.Support;

internal static class ExternalIdentityAssertionTestHelper
{
    internal static ExternalIdentityAssertion Create(
        ProviderType type,
        string providerName,
        string providerKey,
        IReadOnlyDictionary<string, IReadOnlyList<string>> claims) =>
        new(type, providerName, providerKey, claims);

    internal static ExternalIdentityAssertion Create(
        ProviderType type,
        string providerName,
        string providerKey,
        IDictionary<string, string> claims) =>
        new(type, providerName, providerKey, claims);
}
