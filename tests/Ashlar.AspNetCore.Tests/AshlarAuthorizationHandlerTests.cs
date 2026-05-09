using System.Security.Claims;
using Ashlar.AspNetCore.Authorization;
using Ashlar.Authorization.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Moq;

namespace Ashlar.AspNetCore.Tests;

public sealed class AshlarAuthorizationHandlerTests
{
    private Mock<Ashlar.Authorization.Abstractions.IAuthorizationEvaluator> _evaluatorMock;
    private Mock<IHttpContextAccessor> _httpContextAccessorMock;
    private AshlarAuthorizationOptions _options;
    private AshlarAuthorizationHandler _handler;

    [SetUp]
    public void SetUp()
    {
        _evaluatorMock = new Mock<Ashlar.Authorization.Abstractions.IAuthorizationEvaluator>();
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        _options = new AshlarAuthorizationOptions();
        _handler = new AshlarAuthorizationHandler(
            _evaluatorMock.Object,
            _httpContextAccessorMock.Object,
            Microsoft.Extensions.Options.Options.Create(_options));
    }

    [Test]
    public async Task HandleAsyncShouldDoNothingIfUserNotAuthenticated()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity());
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldDoNothingIfUserIdClaimMissing()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity("TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldDoNothingIfUserIdClaimInvalid()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "not-a-guid")], "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldSucceedIfEvaluatorSucceedsForPermission()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _evaluatorMock.Setup(e => e.EvaluateAsync(
                It.Is<AuthorizationEvaluationRequest>(r => r.UserId == userId && r.Permission == "posts:edit"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.HasSucceeded, Is.True);
            Assert.That(context.PendingRequirements, Is.Empty);
        }
    }

    [Test]
    public async Task HandleAsyncShouldSucceedIfEvaluatorSucceedsForRole()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarRoleRequirement("admin", "AdminPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _evaluatorMock.Setup(e => e.EvaluateAsync(
                It.Is<AuthorizationEvaluationRequest>(r => r.UserId == userId && r.Role == "admin"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldResolveScopeFromRouteData()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.ScopeType = "post";
            scope.ScopeIdRouteValueName = "postId";
        });

        var httpContext = new DefaultHttpContext();
        httpContext.GetRouteData().Values["postId"] = "123";
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        _evaluatorMock.Setup(e => e.EvaluateAsync(
                It.Is<AuthorizationEvaluationRequest>(r =>
                    r.UserId == userId &&
                    r.Permission == "posts:edit" &&
                    r.ScopeType == "post" &&
                    r.ScopeId == "123"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldResolveTenantIdFromRouteData()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
        });

        var httpContext = new DefaultHttpContext();
        httpContext.Request.RouteValues["tenantId"] = tenantId.ToString();
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        _evaluatorMock.Setup(e => e.EvaluateAsync(
                It.Is<AuthorizationEvaluationRequest>(r =>
                    r.UserId == userId &&
                    r.TenantId == tenantId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldResolveTenantIdFromClaim()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim("my_tenant_id", tenantId.ToString())
        ], "TestAuth"));

        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "my_tenant_id";
            scope.UseClaimForTenantId = true;
        });

        _evaluatorMock.Setup(e => e.EvaluateAsync(
                It.Is<AuthorizationEvaluationRequest>(r =>
                    r.UserId == userId &&
                    r.TenantId == tenantId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyIfRouteValueMissing()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.ScopeIdRouteValueName = "postId";
        });

        var httpContext = new DefaultHttpContext();
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyIfTenantIdInvalid()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
        });

        var httpContext = new DefaultHttpContext();
        httpContext.Request.RouteValues["tenantId"] = "not-a-guid";

        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldDoNothingIfIdentityIsNull()
    {
        var user = new ClaimsPrincipal();
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldUseFixedScopeIdEvenIfRouteValueNameIsProvided()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.FixedScopeId = "fixed";
            scope.ScopeIdRouteValueName = "postId";
        });

        _evaluatorMock.Setup(e => e.EvaluateAsync(
                It.Is<AuthorizationEvaluationRequest>(r => r.ScopeId == "fixed"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailIfTenantIdRequestedButHttpContextIsNull()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
        });

        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns((HttpContext)null!);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailIfTenantIdRequestedFromClaimButMissing()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
            scope.UseClaimForTenantId = true;
        });

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailIfTenantIdSourceProvidedButRouteValueMissing()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
            scope.UseClaimForTenantId = false;
        });

        var httpContext = new DefaultHttpContext();
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldNotAttemptToResolveScopeIdIfNoRouteValueNameProvided()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.FixedScopeId = "fixed";
            scope.ScopeIdRouteValueName = null;
        });

        _evaluatorMock.Setup(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationEvaluationResult(true, null));

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailIfScopeIdRequestedButHttpContextIsNull()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId.ToString())], "TestAuth"));
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.ScopeIdRouteValueName = "postId";
        });

        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns((HttpContext)null!);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }
}
