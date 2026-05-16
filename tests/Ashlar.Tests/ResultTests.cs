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
