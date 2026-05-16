namespace Ashlar.Tests;

public sealed class ResultTests
{
    [Test]
    public void ImplicitBooleanConversionReflectsSuccess()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Result.Success() ? "success" : "failure", Is.EqualTo("success"));
            Assert.That(Result.Failure("failed") ? "success" : "failure", Is.EqualTo("failure"));
        }
    }
}
