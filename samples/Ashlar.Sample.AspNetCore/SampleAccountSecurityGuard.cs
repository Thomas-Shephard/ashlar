using Dapper;
using Npgsql;

namespace Ashlar.Sample.AspNetCore;

internal sealed class SampleAccountSecurityGuard(NpgsqlDataSource dataSource) : IAccountSecurityGuard
{
    internal const string LastAdminCannotBeChangedToNonSignInStateCode = "last_admin_cannot_be_changed_to_non_sign_in_state";

    public async Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityGuardContext request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(request);
        if (targetState.CanSignIn() || !user.CanSignIn())
        {
            return Result.Success();
        }

        const string userHasAdminGrantSql = """
            SELECT EXISTS (
                SELECT 1
                FROM ashlar_authorization_grants
                WHERE user_id = @UserId
                  AND role = 'admin'
                  AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > NOW())
                  AND ((@TenantId IS NULL AND tenant_id IS NULL) OR tenant_id = @TenantId)
            )
            """;

        const string activeAdminCountSql = """
            SELECT COUNT(DISTINCT u.id)::int
            FROM ashlar_users u
            JOIN ashlar_authorization_grants g ON g.user_id = u.id
            WHERE u.account_state = 'active'
              AND g.role = 'admin'
              AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > NOW())
              AND ((@TenantId IS NULL AND g.tenant_id IS NULL) OR g.tenant_id = @TenantId)
            """;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var tenantId = request.Tenant?.TenantId;
        var userHasAdminGrant = await connection.ExecuteScalarAsync<bool>(new CommandDefinition(
            userHasAdminGrantSql,
            new { UserId = user.Id, TenantId = tenantId },
            cancellationToken: cancellationToken));

        if (!userHasAdminGrant)
        {
            return Result.Success();
        }

        var activeAdminCount = await connection.ExecuteScalarAsync<int>(new CommandDefinition(
            activeAdminCountSql,
            new { TenantId = tenantId },
            cancellationToken: cancellationToken));

        return activeAdminCount <= 1
            ? Result.Failure(new AshlarFailureCode(LastAdminCannotBeChangedToNonSignInStateCode))
            : Result.Success();
    }
}
