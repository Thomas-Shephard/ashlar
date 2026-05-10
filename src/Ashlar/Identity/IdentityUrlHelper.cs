namespace Ashlar.Identity;

internal static class IdentityUrlHelper
{
    public static string? ConstructCallbackUrl(Uri? baseUri, string tokenParam, string token, Guid? userId = null, string? userIdParam = null)
    {
        if (baseUri == null) return null;
        if (!baseUri.IsAbsoluteUri)
        {
            throw new ArgumentException("Callback base URI must be an absolute URI.", nameof(baseUri));
        }

        var builder = new UriBuilder(baseUri);
        var query = System.Web.HttpUtility.ParseQueryString(builder.Query);
        query[tokenParam] = token;

        if (userId.HasValue && !string.IsNullOrWhiteSpace(userIdParam))
        {
            query[userIdParam] = userId.Value.ToString();
        }

        builder.Query = query.ToString();
        return builder.Uri.AbsoluteUri;
    }

    public static string FormatEmailBody(string? template, string? callbackUrl, string? fallbackLabel = null, string? token = null)
    {
        if (template == null) return string.Empty;
        if (callbackUrl != null)
        {
            return template.Contains("{0}")
                ? template.Replace("{0}", callbackUrl)
                : $"{template} {callbackUrl}";
        }

        if (fallbackLabel != null && token != null)
        {
            return $"{fallbackLabel}: {token}";
        }

        return template;
    }
}
