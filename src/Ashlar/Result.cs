using System.Diagnostics.CodeAnalysis;

namespace Ashlar;

/// <summary>
/// Identifies a stable Ashlar failure code.
/// </summary>
public readonly record struct AshlarFailureCode
{
    /// <summary>
    /// Initializes a new stable failure code.
    /// </summary>
    /// <param name="value">Stable failure code used for programmatic handling.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="value" /> is <see langword="null" /> or whitespace.</exception>
    public AshlarFailureCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    /// <summary>
    /// Stable string value used for programmatic failure handling.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the stable failure code string.
    /// </summary>
    /// <returns>Stable failure code string.</returns>
    public override string ToString() => Value;
}

/// <summary>
/// Describes an Ashlar operation failure.
/// </summary>
/// <param name="Code">Stable failure identifier used for programmatic handling.</param>
/// <param name="Message">Optional diagnostic failure message. Prefer <paramref name="Code" /> for branching and map failures to host-owned user-facing copy.</param>
public sealed record AshlarFailure(AshlarFailureCode Code, string? Message = null);

/// <summary>
/// Represents a success or failure outcome for an Ashlar operation.
/// </summary>
public record Result
{
    private protected Result()
    {
        Succeeded = true;
    }

    private protected Result(AshlarFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        ArgumentException.ThrowIfNullOrWhiteSpace(failure.Code.Value);
        FailureDetails = failure;
    }

    /// <summary>
    /// Whether the operation completed successfully.
    /// </summary>
    [MemberNotNullWhen(false, nameof(FailureDetails))]
    public bool Succeeded { get; }
    /// <summary>
    /// Stable failure details when the operation failed.
    /// </summary>
    public AshlarFailure? FailureDetails { get; }
    /// <summary>
    /// Stable failure identifier when the operation failed.
    /// </summary>
    public AshlarFailureCode? FailureCode => FailureDetails?.Code;
    /// <summary>
    /// Optional diagnostic failure message when one is available. It is not guaranteed to be user-display-safe unless the producing API says so.
    /// </summary>
    public string? FailureMessage => FailureDetails?.Message;
    /// <summary>
    /// Diagnostic failure reason. Prefer <see cref="FailureCode" /> for programmatic branching and host-owned display text.
    /// </summary>
    public string? FailureReason => FailureDetails?.Message ?? FailureDetails?.Code.Value;
    /// <summary>
    /// Returns the failure details.
    /// </summary>
    /// <returns>The attached failure details.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the result succeeded.</exception>
    public AshlarFailure GetFailure() =>
        FailureDetails ?? throw new InvalidOperationException("A successful result does not contain failure details.");

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <returns>A successful result without a value.</returns>
    public static Result Success() => new();
    /// <summary>
    /// Creates a successful result with a value.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="value">Successful operation payload.</param>
    /// <returns>A successful typed result.</returns>
    public static Result<T> Success<T>(T value) where T : notnull => Result<T>.CreateSuccess(value);
    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="code">Stable failure identifier to attach to the result.</param>
    /// <param name="message">Optional diagnostic text for the failure. Map failures to host-owned user-facing copy.</param>
    /// <returns>A failed result containing the supplied failure code and message.</returns>
    public static Result Failure(AshlarFailureCode code, string? message = null) => new(new AshlarFailure(code, message));
    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="failure">The failure details to attach.</param>
    /// <returns>A failed result containing the supplied failure details.</returns>
    public static Result Failure(AshlarFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return new Result(failure);
    }

    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="code">Stable failure identifier to attach to the result.</param>
    /// <param name="message">Optional diagnostic text for the failure. Map failures to host-owned user-facing copy.</param>
    /// <returns>A failed typed result containing the supplied failure code and message.</returns>
    public static Result<T> Failure<T>(AshlarFailureCode code, string? message = null) where T : notnull =>
        Result<T>.CreateFailure(new AshlarFailure(code, message));
    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="failure">The failure details to attach.</param>
    /// <returns>A failed typed result containing the supplied failure details.</returns>
    public static Result<T> Failure<T>(AshlarFailure failure) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(failure);
        return Result<T>.CreateFailure(failure);
    }

    /// <summary>
    /// Converts a result to its success flag.
    /// </summary>
    /// <param name="result">Result instance converted to its success flag.</param>
    /// <returns><see langword="true" /> when the result succeeded.</returns>
    public static implicit operator bool(Result result) => result.Succeeded;
}

/// <summary>
/// Represents a success or failure outcome that carries a value on success.
/// </summary>
/// <typeparam name="T">The contained result type.</typeparam>
public record Result<T> : Result where T : notnull
{
    private Result(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Value = value;
    }

    private Result(AshlarFailure failure) : base(failure)
    {
    }

    internal static Result<T> CreateSuccess(T value) => new(value);
    internal static Result<T> CreateFailure(AshlarFailure failure) => new(failure);

    /// <summary>
    /// Successful operation payload, when available.
    /// </summary>
    public T? Value { get; }

    /// <summary>
    /// Attempts to get a non-<see langword="null" /> value from a successful result.
    /// </summary>
    /// <param name="value">Successful operation payload, when available.</param>
    /// <returns><see langword="true" /> when a non-<see langword="null" /> value is available.</returns>
    public bool TryGetValue([NotNullWhen(true)] out T? value)
    {
        value = Value;
        return Succeeded && value is not null;
    }

    /// <summary>
    /// Attempts to get a successful value and otherwise returns the failure details.
    /// </summary>
    /// <param name="value">Successful operation payload, when available.</param>
    /// <param name="failure">Failure details when no value is available.</param>
    /// <returns><see langword="true" /> when a value is available.</returns>
    public bool TryGetValue(
        [NotNullWhen(true)] out T? value,
        [NotNullWhen(false)] out AshlarFailure? failure)
    {
        if (TryGetValue(out value))
        {
            failure = null;
            return true;
        }

        failure = GetFailure();
        return false;
    }
}
