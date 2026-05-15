namespace Ashlar;

/// <summary>
/// Represents the result of an operation.
/// </summary>
/// <param name="Succeeded">Whether the operation succeeded.</param>
/// <param name="FailureReason">An optional reason code for the failure.</param>
public record Result(bool Succeeded, string? FailureReason = null)
{
    public static Result Success() => new(true);
    public static Result<T> Success<T>(T value) => new(true, value);
    public static Result Failure(string reason) => new(false, reason);
    public static Result<T> Failure<T>(string reason) => new(false, default, reason);

    public static implicit operator bool(Result result) => result.Succeeded;
}

/// <summary>
/// Represents the result of an operation that returns a value.
/// </summary>
/// <typeparam name="T">The type of the result value.</typeparam>
/// <param name="Succeeded">Whether the operation succeeded.</param>
/// <param name="Value">The result value if successful.</param>
/// <param name="FailureReason">An optional reason code for the failure.</param>
public record Result<T>(bool Succeeded, T? Value = default, string? FailureReason = null) 
    : Result(Succeeded, FailureReason);
