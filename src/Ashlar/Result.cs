namespace Ashlar;

/// <summary>
/// Represents the result of an operation.
/// </summary>
/// <param name="Succeeded">The succeeded value.</param>
/// <param name="FailureReason">The failure reason value.</param>
public record Result(bool Succeeded, string? FailureReason = null)
{
    /// <summary>
    /// Executes the success operation.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static Result Success() => new(true);
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="value">The result value.</param>
    /// <returns>The operation result.</returns>
    public static Result<T> Success<T>(T value) => new(true, value);
    /// <summary>
    /// Executes the failure operation.
    /// </summary>
    /// <param name="reason">The failure reason.</param>
    /// <returns>The operation result.</returns>
    public static Result Failure(string reason) => new(false, reason);

    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="reason">The failure reason.</param>
    /// <returns>The operation result.</returns>
    public static Result<T> Failure<T>(string reason) => new(false, default, reason);

    /// <summary>
    /// Executes the bool operation.
    /// </summary>
    /// <param name="result">The result to convert.</param>
    /// <returns>The operation result.</returns>
    public static implicit operator bool(Result result) => result.Succeeded;
}

/// <summary>
/// Represents the result of an operation that returns a <paramref name="Value" />.
/// </summary>
/// <typeparam name="T">The contained result type.</typeparam>
/// <param name="Succeeded">The succeeded flag.</param>
/// <param name="Value">The contained result.</param>
/// <param name="FailureReason">The failure reason.</param>
public record Result<T>(bool Succeeded, T? Value = default, string? FailureReason = null)
    : Result(Succeeded, FailureReason);
