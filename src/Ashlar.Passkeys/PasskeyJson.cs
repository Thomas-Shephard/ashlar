using System.Text.Json;

namespace Ashlar.Passkeys;

internal static class PasskeyJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}
