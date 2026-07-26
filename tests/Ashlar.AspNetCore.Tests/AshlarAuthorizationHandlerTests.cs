using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Authorization;
using Ashlar.Authorization.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Moq;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarAuthorizationHandlerTests
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
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(AshlarClaimTypes.SessionId, SessionId.ToString())],
            "Ashlar"));
        SetValidatedSession(user, userId);
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldDoNothingIfUserIdClaimInvalid()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "not-a-guid"),
                new Claim(AshlarClaimTypes.SessionId, SessionId.ToString())
            ],
            "Ashlar"));
        SetValidatedSession(user, userId);
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldSucceedIfEvaluatorSucceedsForPermission()
    {
        var userId = Guid.NewGuid();
        var user = CreateAshlarUser(userId);
        SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId);
        SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId);
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.ScopeType = "post";
            scope.ScopeIdRouteValueName = "postId";
            scope.FixedScopeId = string.Empty;
        });

        var httpContext = SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId, tenantId);
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
        });

        var httpContext = SetValidatedSession(user, userId, tenantId);
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
        var user = CreateAshlarUser(userId, tenantId, new Claim("my_tenant_id", tenantId.ToString()));
        SetValidatedSession(user, userId, tenantId);

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
        var user = CreateAshlarUser(userId);
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.ScopeIdRouteValueName = "postId";
        });

        var httpContext = SetValidatedSession(user, userId);
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyIfTenantIdInvalid()
    {
        var userId = Guid.NewGuid();
        var user = CreateAshlarUser(userId);
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
        });

        var httpContext = SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId);
        SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId);
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
        var user = CreateAshlarUser(userId);
        SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId);
        var requirement = new AshlarPermissionRequirement("posts:edit", "EditPostPolicy");
        var context = new AuthorizationHandlerContext([requirement], user, null);

        _options.AddPermissionPolicy("EditPostPolicy", "posts:edit", scope =>
        {
            scope.TenantIdSource = "tenantId";
            scope.UseClaimForTenantId = false;
        });

        var httpContext = SetValidatedSession(user, userId);
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldNotAttemptToResolveScopeIdIfNoRouteValueNameProvided()
    {
        var userId = Guid.NewGuid();
        var user = CreateAshlarUser(userId);
        SetValidatedSession(user, userId);
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
        var user = CreateAshlarUser(userId);
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

    [Test]
    public async Task HandleAsyncRejectsRawSessionItem()
    {
        var userId = Guid.NewGuid();
        var user = CreateAshlarUser(userId);
        var httpContext = new DefaultHttpContext { User = user };
        httpContext.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] = CreateSession(userId);
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncRejectsAuthenticatedNonAshlarPrincipalWithoutValidatedSession()
    {
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString())],
            "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncRejectsLookalikePrincipalThatIsNotCurrentHttpContextUser()
    {
        var userId = Guid.NewGuid();
        var currentUser = CreateAshlarUser(userId);
        var lookalikeUser = CreateAshlarUser(userId);
        SetValidatedSession(currentUser, userId);
        var context = new AuthorizationHandlerContext(
            [new AshlarPermissionRequirement("p", "policy")],
            lookalikeUser,
            null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task HandleAsyncRejectsMismatchedValidatedSession(bool mismatchUser)
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var user = CreateAshlarUser(userId, tenantId);
        SetValidatedSession(user, mismatchUser ? Guid.NewGuid() : userId, mismatchUser ? tenantId : Guid.NewGuid());
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncRejectsRouteTenantDifferentFromValidatedSession()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var user = CreateAshlarUser(userId, tenantId);
        var httpContext = SetValidatedSession(user, userId, tenantId);
        httpContext.Request.RouteValues["tenantId"] = Guid.NewGuid().ToString();
        _options.AddPermissionPolicy("policy", "p", scope => scope.TenantIdSource = "tenantId");
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
        _evaluatorMock.Verify(e => e.EvaluateAsync(It.IsAny<AuthorizationEvaluationRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task HandleAsyncRejectsRouteTenantWhenValidatedSessionHasNoTenant()
    {
        var userId = Guid.NewGuid();
        var user = CreateAshlarUser(userId);
        var httpContext = SetValidatedSession(user, userId);
        httpContext.Request.RouteValues["tenantId"] = Guid.NewGuid().ToString();
        _options.AddPermissionPolicy("policy", "p", scope => scope.TenantIdSource = "tenantId");
        var context = new AuthorizationHandlerContext([new AshlarPermissionRequirement("p", "policy")], user, null);

        await _handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    private DefaultHttpContext SetValidatedSession(ClaimsPrincipal user, Guid userId, Guid? tenantId = null)
    {
        var httpContext = new DefaultHttpContext { User = user };
        var session = CreateSession(userId, tenantId);
        httpContext.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] =
            (ValidatedAuthenticationSession)Activator.CreateInstance(
                typeof(ValidatedAuthenticationSession),
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                null,
                [session],
                null)!;
        _httpContextAccessorMock.Setup(h => h.HttpContext).Returns(httpContext);
        return httpContext;
    }

    private static ClaimsPrincipal CreateAshlarUser(Guid userId, Guid? tenantId = null, params Claim[] extraClaims)
    {
        var session = CreateSession(userId, tenantId);
        var claims = new List<Claim>(extraClaims)
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(AshlarClaimTypes.SessionId, session.Id.ToString())
        };
        if (tenantId.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.TenantId, tenantId.Value.ToString()));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Ashlar"));
    }

    private static AuthenticationSession CreateSession(Guid userId, Guid? tenantId = null) => new()
    {
        Id = SessionId,
        UserId = userId,
        TenantId = tenantId,
        TokenHash = "hash",
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
    };

    private static readonly Guid SessionId = Guid.NewGuid();
}
