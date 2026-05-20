using Ashlar.Operational.Diagnostics;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class DiagnosticStatusTests
{
    [Test]
    public void AshlarSchemaStatusValuesAreStableForPublicUse()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That((int)AshlarSchemaStatus.Current, Is.Zero);
            Assert.That((int)AshlarSchemaStatus.NotInitialized, Is.EqualTo(1));
            Assert.That((int)AshlarSchemaStatus.PendingMigrations, Is.EqualTo(2));
            Assert.That((int)AshlarSchemaStatus.Unknown, Is.EqualTo(3));
        }
    }
}
