using Ashlar.Identity.Models.Tenants;
using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Connections;

internal static class SqliteCommandExtensions
{
    public static SqliteParameter AddParameter(this SqliteCommand command, string name, object? value)
    {
        return command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    public static SqliteParameter AddGuidParameter(this SqliteCommand command, string name, Guid value)
    {
        return command.AddParameter(name, value.ToString("D"));
    }

    public static SqliteParameter AddNullableGuidParameter(this SqliteCommand command, string name, Guid? value)
    {
        return command.AddParameter(name, value?.ToString("D"));
    }

    public static SqliteParameter AddDateTimeOffsetParameter(this SqliteCommand command, string name, DateTimeOffset value)
    {
        return command.AddParameter(name, value.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
    }

    public static SqliteParameter AddNullableDateTimeOffsetParameter(this SqliteCommand command, string name, DateTimeOffset? value)
    {
        return command.AddParameter(name, value?.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
    }

    public static void AddTenantFilter(this SqliteCommand command, TenantContext? tenant, string column, string parameterName, ref string sql)
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
            sql += $" AND {column} = {parameterName}";
            command.AddNullableGuidParameter(parameterName, tenant.TenantId);
        }
    }

    public static void AddProviderFilter(this SqliteCommand command, AuthenticationProviderKey? provider, string typeColumn, string nameColumn, string typeParameterName, string nameParameterName, ref string sql)
    {
        if (!provider.HasValue)
        {
            return;
        }

        sql += $" AND {typeColumn} = {typeParameterName} AND {nameColumn} = {nameParameterName}";
        command.AddParameter(typeParameterName, provider.Value.TypeValueOrDefault);
        command.AddParameter(nameParameterName, provider.Value.Name);
    }

    public static void AddDateRange(this SqliteCommand command, DateTimeOffset? from, DateTimeOffset? to, string column, string fromParameterName, string toParameterName, ref string sql)
    {
        if (from.HasValue)
        {
            sql += $" AND {column} >= {fromParameterName}";
            command.AddDateTimeOffsetParameter(fromParameterName, from.Value);
        }

        if (to.HasValue)
        {
            sql += $" AND {column} <= {toParameterName}";
            command.AddDateTimeOffsetParameter(toParameterName, to.Value);
        }
    }
}
