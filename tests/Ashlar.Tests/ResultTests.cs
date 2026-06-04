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
        }
    }

    [Test]
    public void GetFailureOrReturnsFailureDetailsWhenPresent()
    {
        var result = Result.Failure(AshlarFailureCodes.InvalidCode, "Invalid code.");

        var failure = result.GetFailureOr(AshlarFailureCodes.ValidationError);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failure.Code, Is.EqualTo(AshlarFailureCodes.InvalidCode));
            Assert.That(failure.Message, Is.EqualTo("Invalid code."));
        }
    }

    [Test]
    public void GetFailureOrReturnsFallbackWhenDetailsAreMissing()
    {
        var failure = Result.Success().GetFailureOr(AshlarFailureCodes.ValidationError);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failure.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(failure.Message, Is.Null);
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
    public void TryGetValueReturnsFalseForFailuresAndMissingValues()
    {
        var failure = Result.Failure<string>(AshlarFailureCodes.ValidationError);
        var missingValue = new Result<string>(true);

        var failedHasValue = failure.TryGetValue(out var failedValue);
        var missingHasValue = missingValue.TryGetValue(out var missing);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failedHasValue, Is.False);
            Assert.That(failedValue, Is.Null);
            Assert.That(missingHasValue, Is.False);
            Assert.That(missing, Is.Null);
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
}
