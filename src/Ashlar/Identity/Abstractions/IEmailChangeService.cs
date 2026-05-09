using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IEmailChangeService
{
    Task<EmailChangeResult> RequestChangeAsync(RequestEmailChangeRequest request, CancellationToken cancellationToken = default);
    Task<EmailChangeResult> ConfirmChangeAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default);
}
