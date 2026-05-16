using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IEmailVerificationService
{
    Task<Result> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default);
    Task<Result> VerifyTokenAsync(Guid userId, string token, CancellationToken cancellationToken = default);
}
