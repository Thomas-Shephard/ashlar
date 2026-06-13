namespace Ashlar.Identity.Features.Services;

internal static class IdentityUrlHelper
{
    /// <summary>
    /// Builds a callback URL containing token and user identifiers.
    /// </summary>
    /// <param name="baseUri">Base callback URI validated by the caller.</param>
    /// <param name="tokenParam">Query parameter name used for the raw token.</param>
    /// <param name="token">Raw token to include in the callback URL. Do not log or persist this value.</param>
    /// <param name="userId">User identifier to include in the callback URL.</param>
    /// <param name="userIdParam">Query parameter name used for the user identifier.</param>
    /// <returns>The callback URL to send to the user.</returns>
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

    /// <summary>
    /// Formats an email body with a callback link.
    /// </summary>
    /// <param name="template">Body template that may contain callback placeholders.</param>
    /// <param name="callbackUrl">Callback URL to insert into the body.</param>
    /// <param name="fallbackLabel">Fallback link label when the template is empty.</param>
    /// <param name="token">Raw token used only for legacy token placeholders. Do not log or persist this value.</param>
    /// <returns>The formatted email body.</returns>
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
