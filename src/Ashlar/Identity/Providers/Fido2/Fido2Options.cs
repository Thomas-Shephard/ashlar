namespace Ashlar.Identity.Providers.Fido2;

public sealed class Fido2Options
{
    /// <summary>
    /// The expected origin for WebAuthn requests (e.g., "https://example.com").
    /// This prevents phishing attacks where a malicious site tricks the user into signing an assertion.
    /// </summary>
    public string ExpectedOrigin { get; set; } = string.Empty;
}
