namespace Ashlar;

/// <summary>
/// Represents a controlled Ashlar operation failure when an API does not return <see cref="Result" />.
/// </summary>
public sealed class AshlarOperationException : InvalidOperationException
{
    /// <summary>
    /// Creates an exception for a controlled Ashlar operation failure.
    /// </summary>
    /// <param name="failureCode">Stable failure identifier carried by the exception.</param>
    /// <param name="message">The failure message.</param>
    public AshlarOperationException(AshlarFailureCode failureCode, string message)
        : base(message)
    {
        FailureCode = failureCode;
    }

    /// <summary>
    /// Gets the stable failure code.
    /// </summary>
    public AshlarFailureCode FailureCode { get; }
}
