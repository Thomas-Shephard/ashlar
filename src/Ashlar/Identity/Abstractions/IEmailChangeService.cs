using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IEmailChangeService
{
    Task<Result> RequestChangeAsync(RequestEmailChangeRequest request, CancellationToken cancellationToken = default);
    Task<Result> ConfirmChangeAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default);
}
