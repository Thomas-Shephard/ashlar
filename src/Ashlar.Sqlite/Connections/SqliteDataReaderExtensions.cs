using Microsoft.Data.Sqlite;

namespace Ashlar.Sqlite.Connections;

internal static class SqliteDataReaderExtensions
{
    public static Guid GetGuidFromText(this SqliteDataReader reader, string name)
    {
        return Guid.Parse(reader.GetString(reader.GetOrdinal(name)));
    }

    public static Guid? GetNullableGuidFromText(this SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : Guid.Parse(reader.GetString(ordinal));
    }

    public static DateTimeOffset GetDateTimeOffsetFromText(this SqliteDataReader reader, string name)
    {
        return DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal(name)), System.Globalization.CultureInfo.InvariantCulture);
    }

    public static DateTimeOffset? GetNullableDateTimeOffsetFromText(this SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : DateTimeOffset.Parse(reader.GetString(ordinal), System.Globalization.CultureInfo.InvariantCulture);
    }

    public static string? GetNullableString(this SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    public static int GetInt32ByName(this SqliteDataReader reader, string name)
    {
        return reader.GetInt32(reader.GetOrdinal(name));
    }

    public static bool GetBooleanFromInteger(this SqliteDataReader reader, string name)
    {
        return reader.GetInt32ByName(name) != 0;
    }
}
