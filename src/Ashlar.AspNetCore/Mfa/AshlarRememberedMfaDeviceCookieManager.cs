using Ashlar.Auditing;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Mfa;

/// <summary>
/// Provides ASP.NET Core remembered MFA device cookie behavior.
/// </summary>
/// <param name="rememberedMfaDevices">The remembered MFA device service.</param>
/// <param name="options">The cookie options.</param>
public sealed class AshlarRememberedMfaDeviceCookieManager(
    IRememberedMfaDeviceService rememberedMfaDevices,
    IOptions<AshlarRememberedMfaDeviceCookieOptions> options)
    : IAshlarRememberedMfaDeviceCookieManager
{
    private readonly IRememberedMfaDeviceService _rememberedMfaDevices = rememberedMfaDevices ?? throw new ArgumentNullException(nameof(rememberedMfaDevices));
    private readonly AshlarRememberedMfaDeviceCookieOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    public async Task<RememberedMfaDeviceSummary> IssueAfterSuccessfulMfaAsync(
        HttpContext httpContext,
        AuthenticationContext context,
        MfaAuthenticationResult mfaResult,
        CreateRememberedMfaDeviceRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(mfaResult);
        if (mfaResult.Status != MfaAuthenticationStatus.Succeeded || mfaResult.User == null || !mfaResult.FreshMfaSatisfied)
        {
            throw new ArgumentException("A successful fresh MFA authentication result with a user is required.", nameof(mfaResult));
        }

        if (mfaResult.User.Id == Guid.Empty) throw new ArgumentException("The MFA authentication result user ID cannot be empty.", nameof(mfaResult));

        var (creationRequest, audit) = CreateRequestFromAuthenticationContext(context, mfaResult.User.Id, request);
        var result = await _rememberedMfaDevices.CreateAfterSuccessfulMfaAsync(mfaResult, creationRequest, cancellationToken);
        if (!result.TryGetValue(out var created, out var failure))
        {
            throw new AshlarOperationException(failure.Code, failure.Message ?? failure.Code.Value);
        }

        var cookieOptions = _options.Cookie.Build(httpContext);
        cookieOptions.Expires = created.Device.ExpiresAt;
        try
        {
            httpContext.Response.Cookies.Append(_options.CookieName, created.Token, cookieOptions);
        }
        catch (Exception exception)
        {
            await RollBackRememberedDeviceAsync(created, audit, exception);
            throw;
        }

        return created.Device;
    }

    private async Task RollBackRememberedDeviceAsync(
        RememberedMfaDeviceCreated created,
        AuditContext audit,
        Exception originalException)
    {
        try
        {
            var ownerAudit = audit with { ActorUserId = created.Device.UserId };
            if (!await _rememberedMfaDevices.RevokeCurrentAsync(
                new RevokeCurrentRememberedMfaDeviceRequest(
                    created.Device.UserId,
                    created.Token,
                    created.Device.TenantId is { } tenantId ? new TenantContext(tenantId) : TenantContext.Global,
                    ownerAudit,
                    "cookie-delivery-failed"),
                CancellationToken.None))
            {
                throw new InvalidOperationException("Remembered MFA device rollback did not revoke the device.");
            }
        }
        catch (Exception rollbackException)
        {
            originalException.Data["AshlarRememberedMfaDeviceRollbackException"] = rollbackException;
        }
    }

    public AuthenticationContext EnrichContext(HttpContext httpContext, AuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(context);

        return httpContext.Request.Cookies.TryGetValue(_options.CookieName, out var token) && !string.IsNullOrWhiteSpace(token)
            ? context.WithRememberedMfaDeviceToken(token)
            : context;
    }

    public void Clear(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        httpContext.Response.Cookies.Delete(_options.CookieName, _options.Cookie.Build(httpContext));
    }

    public async Task<bool> RevokeCurrentAsync(
        HttpContext httpContext,
        Guid userId,
        TenantContext? tenant = null,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        if (!httpContext.Request.Cookies.TryGetValue(_options.CookieName, out var token) || string.IsNullOrWhiteSpace(token))
        {
            Clear(httpContext);
            return false;
        }

        var audit = CreateAuditContextFromHttpContext(httpContext, userId);
        var revoked = await _rememberedMfaDevices.RevokeCurrentAsync(
            new RevokeCurrentRememberedMfaDeviceRequest(userId, token, tenant ?? TenantContext.Global, audit, reason),
            cancellationToken);

        Clear(httpContext);
        return revoked;
    }

    private static (CreateRememberedMfaDeviceRequest Request, AuditContext Audit) CreateRequestFromAuthenticationContext(
        AuthenticationContext context,
        Guid userId,
        CreateRememberedMfaDeviceRequest? request)
    {
        var audit = new AuditContext(
            ActorUserId: userId,
            IpAddress: context.IpAddress,
            UserAgent: context.UserAgent,
            CorrelationId: context.CorrelationId);
        return ((request ?? new CreateRememberedMfaDeviceRequest()) with
        {
            Tenant = context.TenantId.HasValue ? new TenantContext(context.TenantId.Value) : null,
            Audit = audit
        }, audit);
    }

    private static AuditContext CreateAuditContextFromHttpContext(HttpContext httpContext, Guid? actorUserId)
    {
        return new AuditContext(
            ActorUserId: actorUserId,
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }
}
