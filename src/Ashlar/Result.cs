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
/// <param name="Succeeded">Whether the operation completed successfully.</param>
/// <param name="FailureDetails">Stable failure details when the operation failed.</param>
public record Result(bool Succeeded, AshlarFailure? FailureDetails = null)
{
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
    /// Returns attached failure details, or creates fallback details when none were supplied.
    /// </summary>
    /// <param name="fallback">Failure identifier to use when no structured failure is available.</param>
    /// <returns>Attached or fallback failure details.</returns>
    public AshlarFailure GetFailureOr(AshlarFailureCode fallback) => FailureDetails ?? new AshlarFailure(fallback);

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <returns>A successful result without a value.</returns>
    public static Result Success() => new(true);
    /// <summary>
    /// Creates a successful result with a value.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="value">Successful operation payload.</param>
    /// <returns>A successful typed result.</returns>
    public static Result<T> Success<T>(T value) => new(true, value);
    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="code">Stable failure identifier to attach to the result.</param>
    /// <param name="message">Optional diagnostic text for the failure. Map failures to host-owned user-facing copy.</param>
    /// <returns>A failed result containing the supplied failure code and message.</returns>
    public static Result Failure(AshlarFailureCode code, string? message = null) => new(false, new AshlarFailure(code, message));
    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="failure">The failure details to attach.</param>
    /// <returns>A failed result containing the supplied failure details.</returns>
    public static Result Failure(AshlarFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return new Result(false, failure);
    }

    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="code">Stable failure identifier to attach to the result.</param>
    /// <param name="message">Optional diagnostic text for the failure. Map failures to host-owned user-facing copy.</param>
    /// <returns>A failed typed result containing the supplied failure code and message.</returns>
    public static Result<T> Failure<T>(AshlarFailureCode code, string? message = null) => new(false, default, new AshlarFailure(code, message));
    /// <summary>
    /// Creates a failed typed result.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="failure">The failure details to attach.</param>
    /// <returns>A failed typed result containing the supplied failure details.</returns>
    public static Result<T> Failure<T>(AshlarFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        return new Result<T>(false, default, failure);
    }

    /// <summary>
    /// Converts a result to its success flag.
    /// </summary>
    /// <param name="result">Result instance converted to its success flag.</param>
    /// <returns><see langword="true" /> when the result succeeded.</returns>
    public static implicit operator bool(Result result) => result.Succeeded;
}

/// <summary>
/// Represents a success or failure outcome that may carry <paramref name="Value" />.
/// </summary>
/// <typeparam name="T">The contained result type.</typeparam>
/// <param name="Succeeded">Whether the operation completed successfully.</param>
/// <param name="Value">Successful operation payload, when available.</param>
/// <param name="FailureDetails">Stable failure details when the operation failed.</param>
public record Result<T>(bool Succeeded, T? Value = default, AshlarFailure? FailureDetails = null)
    : Result(Succeeded, FailureDetails)
{
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
}
