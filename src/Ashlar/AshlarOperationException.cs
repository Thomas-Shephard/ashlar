namespace Ashlar;

/// <summary>
/// Represents a controlled Ashlar operation failure when an API does not return <see cref="Result" />.
/// </summary>
/// <param name="failureCode">Stable failure identifier carried by the exception.</param>
/// <param name="message">The failure message.</param>
/// <remarks>
/// Creates an exception for a controlled Ashlar operation failure.
/// </remarks>
public sealed class AshlarOperationException(AshlarFailureCode failureCode, string message) : InvalidOperationException(message)
{

    /// <summary>
    /// Gets the stable failure code.
    /// </summary>
    public AshlarFailureCode FailureCode { get; } = failureCode;
}
