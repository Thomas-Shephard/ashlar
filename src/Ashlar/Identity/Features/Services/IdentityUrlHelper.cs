namespace Ashlar.Identity.Features.Services;

internal static class IdentityUrlHelper
{
    /// <summary>
    /// Performs the construct callback url operation and returns the result.
    /// </summary>
    /// <param name="baseUri">The base uri value.</param>
    /// <param name="tokenParam">The token param value.</param>
    /// <param name="token">The token value.</param>
    /// <param name="userId">The user id value.</param>
    /// <param name="userIdParam">The user id param value.</param>
    /// <returns>The operation result.</returns>
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
    /// Performs the format email body operation and returns the result.
    /// </summary>
    /// <param name="template">The template value.</param>
    /// <param name="callbackUrl">The callback url value.</param>
    /// <param name="fallbackLabel">The fallback label value.</param>
    /// <param name="token">The token value.</param>
    /// <returns>The operation result.</returns>
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



