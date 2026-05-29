namespace Ashlar;

/// <summary>
/// Represents a controlled Ashlar operation failure when an API does not return <see cref="Result" />.
/// </summary>
public sealed class AshlarOperationException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarOperationException" /> class.
    /// </summary>
    /// <param name="failureCode">The stable failure code.</param>
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
