using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity.Models;

public enum MfaAuthenticationStatus
{
    Failed = 0,
    Succeeded = 1,
    MfaRequired = 2,
    HandshakeIncomplete = 3
}

public sealed record MfaAuthenticationResult(
    MfaAuthenticationStatus Status,
    IUser? User = null,
    string? HandshakeToken = null,
    IEnumerable<string>? RequiredFactors = null,
    IDictionary<string, string>? Claims = null,
    string? ErrorMessage = null);
