using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IEmailVerificationService
{
    Task<EmailVerificationResult> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default);
    Task<EmailVerificationResult> VerifyTokenAsync(Guid userId, string token, CancellationToken cancellationToken = default);
}
