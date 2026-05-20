namespace Ashlar;

/// <summary>
/// Identifies a stable Ashlar failure code.
/// </summary>
public readonly record struct AshlarFailureCode
{
    /// <summary>
    /// Initializes a new stable failure code.
    /// </summary>
    /// <param name="value">The stable code value.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="value" /> is <see langword="null" /> or whitespace.</exception>
    public AshlarFailureCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    /// <summary>
    /// Gets the stable code value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the stable code value.
    /// </summary>
    /// <returns>The stable code value.</returns>
    public override string ToString() => Value;
}

/// <summary>
/// Describes an Ashlar operation failure.
/// </summary>
/// <param name="Code">The stable failure code.</param>
/// <param name="Message">An optional human-readable failure message.</param>
public sealed record AshlarFailure(AshlarFailureCode Code, string? Message = null);

/// <summary>
/// Represents the result of an operation.
/// </summary>
/// <param name="Succeeded">The succeeded value.</param>
/// <param name="FailureDetails">The failure information.</param>
public record Result(bool Succeeded, AshlarFailure? FailureDetails = null)
{
    /// <summary>
    /// Gets the stable failure code, when the operation failed.
    /// </summary>
    public AshlarFailureCode? FailureCode => FailureDetails?.Code;
    /// <summary>
    /// Gets the human-readable failure message, when one is available.
    /// </summary>
    public string? FailureMessage => FailureDetails?.Message;
    /// <summary>
    /// Gets a display-oriented failure reason. Prefer <see cref="FailureCode" /> for branching.
    /// </summary>
    public string? FailureReason => FailureDetails?.Message ?? FailureDetails?.Code.Value;

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
    /// Creates a failed result.
    /// </summary>
    /// <param name="code">The stable failure code.</param>
    /// <param name="message">The optional human-readable failure message.</param>
    /// <returns>The operation result.</returns>
    public static Result Failure(AshlarFailureCode code, string? message = null) => new(false, new AshlarFailure(code, message));
    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="failure">The failure value.</param>
    /// <returns>The operation result.</returns>
    public static Result Failure(AshlarFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return new Result(false, failure);
    }

    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="code">The stable failure code.</param>
    /// <param name="message">The optional human-readable failure message.</param>
    /// <returns>The operation result.</returns>
    public static Result<T> Failure<T>(AshlarFailureCode code, string? message = null) => new(false, default, new AshlarFailure(code, message));
    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="failure">The failure value.</param>
    /// <returns>The operation result.</returns>
    public static Result<T> Failure<T>(AshlarFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return new Result<T>(false, default, failure);
    }

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
/// <param name="FailureDetails">The failure information.</param>
public record Result<T>(bool Succeeded, T? Value = default, AshlarFailure? FailureDetails = null)
    : Result(Succeeded, FailureDetails);


