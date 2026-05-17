using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite;

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
}
