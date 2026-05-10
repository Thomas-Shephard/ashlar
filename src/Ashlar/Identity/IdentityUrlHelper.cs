namespace Ashlar.Identity;

internal static class IdentityUrlHelper
{
    public static string? ConstructCallbackUrl(Uri? baseUri, Guid userId, string token, string tokenParam, string userIdParam)
    {
        if (baseUri == null) return null;
        if (!baseUri.IsAbsoluteUri)
        {
            throw new ArgumentException("Callback base URI must be an absolute URI.", nameof(baseUri));
        }

        var builder = new UriBuilder(baseUri);
        var query = System.Web.HttpUtility.ParseQueryString(builder.Query);
        query[tokenParam] = token;
        query[userIdParam] = userId.ToString();
        builder.Query = query.ToString();
        return builder.Uri.AbsoluteUri;
    }

    public static string FormatEmailBody(string template, string? callbackUrl, string fallbackLabel, string token)
    {
        if (callbackUrl != null)
        {
            return template.Contains("{0}")
                ? template.Replace("{0}", callbackUrl)
                : $"{template} {callbackUrl}";
        }

        return $"{fallbackLabel}: {token}";
    }
}
