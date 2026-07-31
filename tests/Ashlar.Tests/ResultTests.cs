namespace Ashlar.Tests;

internal sealed class ResultTests
{
    [Test]
    public void ImplicitBooleanConversionReflectsSuccess()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Result.Success() ? "success" : "failure", Is.EqualTo("success"));
            Assert.That(Result.Failure(AshlarFailureCodes.ValidationError) ? "success" : "failure", Is.EqualTo("failure"));
        }
    }

    [Test]
    public void FailureExposesStableCodeAndOptionalMessage()
    {
        var result = Result.Failure(AshlarFailureCodes.InvalidCallbackUri, "Callback URI is not allowed.");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCallbackUri));
            Assert.That(result.FailureMessage, Is.EqualTo("Callback URI is not allowed."));
            Assert.That(result.FailureReason, Is.EqualTo("Callback URI is not allowed."));
        }
    }

    [Test]
    public void FailureWithoutMessageUsesCodeAsReason()
    {
        var result = Result.Failure(AshlarFailureCodes.InvalidCode);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCode));
            Assert.That(result.FailureMessage, Is.Null);
            Assert.That(result.FailureReason, Is.EqualTo(AshlarFailureCodes.InvalidCode.Value));
            Assert.That(result.FailureCode?.ToString(), Is.EqualTo(AshlarFailureCodes.InvalidCode.Value));
        }
    }

    [Test]
    public void SuccessHasNoFailureDetails()
    {
        var result = Result.Success();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.Null);
            Assert.That(result.FailureMessage, Is.Null);
            Assert.That(result.FailureReason, Is.Null);
            Assert.That(result.FailureDetails, Is.Null);
        }
    }

    [Test]
    public void TryGetValueReturnsValueForSuccessfulResult()
    {
        var result = Result.Success("value");

        var succeeded = result.TryGetValue(out var value);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(succeeded, Is.True);
            Assert.That(value, Is.EqualTo("value"));
        }
    }

    [Test]
    public void TryGetValueReturnsFalseForFailures()
    {
        var failure = Result.Failure<string>(AshlarFailureCodes.ValidationError);

        var failedHasValue = failure.TryGetValue(out var failedValue, out var failureDetails);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failedHasValue, Is.False);
            Assert.That(failedValue, Is.Null);
            Assert.That(failureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public void GetFailureReturnsDetailsAndRejectsSuccess()
    {
        var failure = Result.Failure(AshlarFailureCodes.InvalidCode);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failure.GetFailure().Code, Is.EqualTo(AshlarFailureCodes.InvalidCode));
            Assert.That(() => Result.Success().GetFailure(), Throws.InvalidOperationException);
        }
    }

    [Test]
    public void TryGetValueReturnsNoFailureForSuccess()
    {
        var succeeded = Result.Success("value").TryGetValue(out var value, out var failure);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(succeeded, Is.True);
            Assert.That(value, Is.EqualTo("value"));
            Assert.That(failure, Is.Null);
        }
    }

    [Test]
    public void TryGetValueRejectsABypassedInvalidState()
    {
        var invalid = (Result<string>)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(Result<string>));

        Assert.That(
            () => invalid.TryGetValue(out _, out _),
            Throws.InvalidOperationException);
    }

    [Test]
    public void SuccessRejectsNullValues()
    {
        Assert.That(() => Result.Success<string>(null!), Throws.TypeOf<ArgumentNullException>());
    }

    [Test]
    public void ConstructorsAreNotPublic()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(Result).GetConstructors(), Is.Empty);
            Assert.That(typeof(Result<string>).GetConstructors(), Is.Empty);
        }
    }

    [Test]
    public void TypedFactoriesCreateValidSuccessAndFailureResults()
    {
        var success = Result.Success(0);
        var failure = Result.Failure<int>(AshlarFailureCodes.ValidationError);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(success.TryGetValue(out var value), Is.True);
            Assert.That(value, Is.Zero);
            Assert.That(failure.TryGetValue(out _), Is.False);
        }
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void FailureCodeRejectsNullOrWhitespaceValues(string? value)
    {
        Assert.That(() => new AshlarFailureCode(value!), Throws.InstanceOf<ArgumentException>());
    }

    [Test]
    public void FailureRejectsNullFailureDetails()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(() => Result.Failure(null!), Throws.TypeOf<ArgumentNullException>());
            Assert.That(() => Result.Failure<string>(null!), Throws.TypeOf<ArgumentNullException>());
        }
    }

    [Test]
    public void FailureRejectsDefaultFailureCodes()
    {
        var failure = new AshlarFailure(default);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(() => Result.Failure(default(AshlarFailureCode)), Throws.TypeOf<ArgumentNullException>());
            Assert.That(() => Result.Failure(failure), Throws.TypeOf<ArgumentNullException>());
            Assert.That(() => Result.Failure<string>(default(AshlarFailureCode)), Throws.TypeOf<ArgumentNullException>());
            Assert.That(() => Result.Failure<string>(failure), Throws.TypeOf<ArgumentNullException>());
        }
    }
}
