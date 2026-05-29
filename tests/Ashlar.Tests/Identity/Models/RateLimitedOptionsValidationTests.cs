using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Tests.Identity.Models;

internal sealed class RateLimitedOptionsValidationTests
{
    [Test]
    public void EmailVerificationOptionsValidateAllInvalidShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions()), Is.True);
            Assert.That(EmailVerificationOptions.Validate(null), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { Expiration = TimeSpan.Zero }), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { RequestRateLimit = InvalidRule() }), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { VerificationRateLimit = InvalidRule() }), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { Subject = " " }), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { EmailTextTemplate = " " }), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { TokenParameterName = " " }), Is.False);
            Assert.That(EmailVerificationOptions.Validate(new EmailVerificationOptions { UserIdParameterName = " " }), Is.False);
        }
    }

    [Test]
    public void EmailChangeOptionsValidateAllInvalidShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions()), Is.True);
            Assert.That(EmailChangeOptions.Validate(null), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { Expiration = TimeSpan.Zero }), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { RequestRateLimit = InvalidRule() }), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { VerificationRateLimit = InvalidRule() }), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { Subject = " " }), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { EmailTextTemplate = " " }), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { TokenParameterName = " " }), Is.False);
            Assert.That(EmailChangeOptions.Validate(new EmailChangeOptions { UserIdParameterName = " " }), Is.False);
        }
    }

    [Test]
    public void InvitationOptionsValidateAllInvalidShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(InvitationOptions.Validate(new InvitationOptions()), Is.True);
            Assert.That(InvitationOptions.Validate(null), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { DefaultExpiry = TimeSpan.Zero }), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { CreationRateLimit = InvalidRule() }), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { PreviewRateLimit = InvalidRule() }), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { AcceptanceRateLimit = InvalidRule() }), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { EmailSubject = " " }), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { EmailTextTemplate = " " }), Is.False);
            Assert.That(InvitationOptions.Validate(new InvitationOptions { TokenParameterName = " " }), Is.False);
        }
    }

    [Test]
    public void BootstrapOptionsValidateAllInvalidShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions()), Is.True);
            Assert.That(BootstrapOptions.Validate(null), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = null! }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { AttemptRateLimit = null! }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { AttemptRateLimit = InvalidRule() }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = [null!] }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = [new BootstrapGrantTemplate()] }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = [new BootstrapGrantTemplate { Role = "admin", Permission = "manage" }] }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = [new BootstrapGrantTemplate { Role = "admin", ScopeType = "project" }] }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = [new BootstrapGrantTemplate { Permission = "manage", ScopeId = "alpha" }] }), Is.False);
            Assert.That(BootstrapOptions.Validate(new BootstrapOptions { Grants = [new BootstrapGrantTemplate { Role = "admin", ScopeType = "project", ScopeId = "alpha" }] }), Is.True);
        }
    }

    [Test]
    public void RecoveryCodeOptionsValidateAllInvalidShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(RecoveryCodeOptions.Validate(new RecoveryCodeOptions()), Is.True);
            Assert.That(RecoveryCodeOptions.Validate(null), Is.False);
            Assert.That(RecoveryCodeOptions.Validate(new RecoveryCodeOptions { CodeCount = 0 }), Is.False);
            Assert.That(RecoveryCodeOptions.Validate(new RecoveryCodeOptions { CodeLength = 0 }), Is.False);
            Assert.That(RecoveryCodeOptions.Validate(new RecoveryCodeOptions { GroupSize = 0 }), Is.False);
            Assert.That(RecoveryCodeOptions.Validate(new RecoveryCodeOptions { ProviderKey = default }), Is.False);
            Assert.That(RecoveryCodeOptions.Validate(new RecoveryCodeOptions { ExpiresAfter = TimeSpan.Zero }), Is.False);
        }
    }

    [Test]
    public void AuthenticationHandshakeOptionsValidateAllInvalidShapes()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationHandshakeOptions.Validate(new AuthenticationHandshakeOptions()), Is.True);
            Assert.That(AuthenticationHandshakeOptions.Validate(null), Is.False);
            Assert.That(AuthenticationHandshakeOptions.Validate(new AuthenticationHandshakeOptions { Expiry = TimeSpan.Zero }), Is.False);
            Assert.That(AuthenticationHandshakeOptions.Validate(new AuthenticationHandshakeOptions { VerificationRateLimit = null! }), Is.False);
            Assert.That(AuthenticationHandshakeOptions.Validate(new AuthenticationHandshakeOptions { VerificationRateLimit = InvalidRule() }), Is.False);
        }
    }

    private static RateLimitRule InvalidRule()
    {
        return new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) };
    }
}
