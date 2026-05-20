using Ashlar.Testing;
using Microsoft.Extensions.Logging;

namespace Ashlar.Tests.Testing;

internal sealed class RecordingLoggerTests
{
    [Test]
    public void RecordingLoggerShouldCaptureFormattedLogEntryAndScope()
    {
        var logger = new RecordingLogger();
        var exception = new InvalidOperationException("failure");

        using (logger.BeginScope("scope"))
        {
            logger.Log(
                LogLevel.Warning,
                new EventId(1, "Test"),
                "state",
                exception,
                static (state, _) => $"message:{state}");
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(logger.IsEnabled(LogLevel.Warning), Is.True);
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Level, Is.EqualTo(LogLevel.Warning));
            Assert.That(logger.Entries[0].Message, Is.EqualTo("message:state"));
            Assert.That(logger.Entries[0].Exception, Is.SameAs(exception));
        }
    }

    [Test]
    public void GenericRecordingLoggerShouldCaptureFormattedLogEntry()
    {
        var logger = new RecordingLogger<RecordingLoggerTests>();

        logger.Log(
            LogLevel.Information,
            new EventId(2, "GenericTest"),
            "generic",
            null,
            static (state, _) => $"message:{state}");

        Assert.That(logger.Entries.Single().Message, Is.EqualTo("message:generic"));
    }
}
