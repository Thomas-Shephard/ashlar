using Ashlar.Operational;

namespace Ashlar.Tests.Operational;

internal sealed class AshlarCleanupResultTests
{
    [Test]
    public void EmptyHasZeroTotal()
    {
        Assert.That(AshlarCleanupResult.Empty.Total, Is.Zero);
    }

    [Test]
    public void TotalSumsAllCategories()
    {
        var result = new AshlarCleanupResult(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20);

        Assert.That(result.Total, Is.EqualTo(210));
    }

    [Test]
    public void AddSumsCategoryCounts()
    {
        var result = new AshlarCleanupResult(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
            .Add(new AshlarCleanupResult(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2));

        Assert.That(result, Is.EqualTo(new AshlarCleanupResult(3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3)));
    }

    [Test]
    public void AddThrowsForNullResult()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => AshlarCleanupResult.Empty.Add(null!));
    }
}
