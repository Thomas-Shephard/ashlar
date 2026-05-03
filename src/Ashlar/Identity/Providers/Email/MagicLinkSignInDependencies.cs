using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

public sealed record MagicLinkSignInDependencies(
    IIdentityService IdentityService,
    IIdentityRepository Repository,
    IEmailSender EmailSender,
    IAuthenticationRateLimiter RateLimiter,
    ISecureTokenGenerator TokenGenerator,
    MagicLinkAuthenticationProvider Provider,
    ISecurityEventSink SecurityEventSink,
    ISecretProtector SecretProtector,
    TimeProvider TimeProvider);
