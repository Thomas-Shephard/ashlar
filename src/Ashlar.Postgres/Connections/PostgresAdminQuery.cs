using Dapper;
using Ashlar.Identity.Models.Tenants;

namespace Ashlar.Postgres.Connections;

internal static class PostgresAdminQuery
{
    public static async Task<IReadOnlyList<T>> QueryAsync<T>(
        IPostgresConnectionProvider connectionProvider,
        string sql,
        object? parameters,
        CancellationToken cancellationToken)
    {
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            var rows = await connectionHandle.Connection.QueryAsync<T>(command);
            return rows.ToList().AsReadOnly();
        }
    }

    public static async Task<T?> QuerySingleAsync<T>(
        IPostgresConnectionProvider connectionProvider,
        string sql,
        object? parameters,
        CancellationToken cancellationToken)
    {
        var connectionHandle = await connectionProvider.GetConnectionAsync(cancellationToken);
        await using (connectionHandle)
        {
            var command = new CommandDefinition(sql, parameters, transaction: connectionHandle.Transaction, cancellationToken: cancellationToken);
            return await connectionHandle.Connection.QueryFirstOrDefaultAsync<T>(command);
        }
    }

    public static void AddTenantFilter(TenantContext? tenant, string column, string parameterName, ref string sql, DynamicParameters parameters)
    {
        if (tenant == null)
        {
            return;
        }

        if (tenant.TenantId == null)
        {
            sql += $" AND {column} IS NULL";
        }
        else
        {
            sql += $" AND {column} = @{parameterName}";
            parameters.Add(parameterName, tenant.TenantId);
        }
    }

    public static void AddProviderFilter(AuthenticationProviderKey? provider, string typeColumn, string nameColumn, string typeParameterName, string nameParameterName, ref string sql, DynamicParameters parameters)
    {
        if (!provider.HasValue)
        {
            return;
        }

        sql += $" AND {typeColumn} = @{typeParameterName} AND {nameColumn} = @{nameParameterName}";
        parameters.Add(typeParameterName, provider.Value.TypeValueOrDefault);
        parameters.Add(nameParameterName, provider.Value.Name);
    }

    public static void AddDateRange(DateTimeOffset? from, DateTimeOffset? to, string column, string fromParameterName, string toParameterName, ref string sql, DynamicParameters parameters)
    {
        if (from.HasValue)
        {
            sql += $" AND {column} >= @{fromParameterName}";
            parameters.Add(fromParameterName, from.Value);
        }

        if (to.HasValue)
        {
            sql += $" AND {column} <= @{toParameterName}";
            parameters.Add(toParameterName, to.Value);
        }
    }

    public static DateTimeOffset ToDateTimeOffset(DateTime value)
    {
        return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
    }

    public static DateTimeOffset? ToNullableDateTimeOffset(DateTime? value)
    {
        return value == null ? null : ToDateTimeOffset(value.Value);
    }
}
