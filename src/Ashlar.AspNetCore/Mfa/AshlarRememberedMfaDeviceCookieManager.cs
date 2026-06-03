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

        var userId = mfaResult.User.Id;
        if (userId == Guid.Empty) throw new ArgumentException("The MFA authentication result user ID cannot be empty.", nameof(mfaResult));

        var creationRequest = request ?? CreateRequestFromAuthenticationContext(context, userId);
        var result = await _rememberedMfaDevices.CreateAsync(userId, creationRequest, cancellationToken);
        if (!result.Succeeded || result.Value == null)
        {
            throw new AshlarOperationException(result.FailureCode ?? AshlarFailureCodes.ValidationError, result.FailureReason ?? "Failed to create remembered MFA device.");
        }

        var cookieOptions = _options.Cookie.Build(httpContext);
        cookieOptions.Expires = result.Value.Device.ExpiresAt;
        httpContext.Response.Cookies.Append(_options.CookieName, result.Value.Token, cookieOptions);
        return result.Value.Device;
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
        var validation = await _rememberedMfaDevices.ValidateAsync(
            userId,
            new ValidateRememberedMfaDeviceRequest(token)
            {
                Tenant = tenant,
                Audit = audit
            },
            cancellationToken);

        var revoked = false;
        if (validation.Succeeded && validation.Device != null)
        {
            revoked = await _rememberedMfaDevices.RevokeAsync(
                userId,
                new RevokeRememberedMfaDeviceRequest(validation.Device.Id)
                {
                    Tenant = tenant,
                    Reason = reason,
                    Audit = audit
                },
                cancellationToken);
        }

        Clear(httpContext);
        return revoked;
    }

    private static CreateRememberedMfaDeviceRequest CreateRequestFromAuthenticationContext(AuthenticationContext context, Guid userId)
    {
        return new CreateRememberedMfaDeviceRequest
        {
            Tenant = context.TenantId.HasValue ? new TenantContext(context.TenantId.Value) : null,
            Audit = new AuditContext(
                ActorUserId: userId,
                IpAddress: context.IpAddress,
                UserAgent: context.UserAgent,
                CorrelationId: context.CorrelationId)
        };
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
