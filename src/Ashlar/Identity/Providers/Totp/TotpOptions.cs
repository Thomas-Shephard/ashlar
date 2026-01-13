namespace Ashlar.Identity.Providers.Totp;

public sealed class TotpOptions
{
    /// <summary>
    /// The time step in seconds. Defaults to 30.
    /// </summary>
    public int Period { get; set; } = 30;

    /// <summary>
    /// The number of digits for the TOTP code. Defaults to 6.
    /// RFC 6238 allows for 6 or 8 digits.
    /// </summary>
    public int Digits
    {
        get;
        set
        {
            if (value is not (6 or 8))
            {
                throw new ArgumentException("TOTP digits must be either 6 or 8.", nameof(value));
            }

            field = value;
        }
    } = 6;
}
