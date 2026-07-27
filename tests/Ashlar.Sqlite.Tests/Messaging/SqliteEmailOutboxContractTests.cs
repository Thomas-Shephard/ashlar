using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.Data.Sqlite;
using System.Globalization;

namespace Ashlar.Sqlite.Tests.Messaging;

internal sealed class SqliteEmailOutboxContractTests : EmailOutboxContractTests
{
    private SqliteContractDatabase? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(ContractNow);
        _database = await SqliteContractDatabase.CreateAsync(services =>
        {
            services.AddSingleton<TimeProvider>(_timeProvider);
            services.AddSingleton<RecordingEmailTransport>();
            services.AddSingleton<RecordingSecretProtector>();
            services.AddSingleton<Ashlar.Security.Encryption.ISecretProtector>(provider => provider.GetRequiredService<RecordingSecretProtector>());
            services.AddAshlarSqliteEmailOutboxDispatcher<RecordingEmailTransport>(options =>
            {
                options.BatchSize = 2;
                options.InitialRetryDelay = TimeSpan.FromMinutes(1);
            });
        });
        return _database.ServiceProvider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        _database?.Delete();
        _database = null;
        return Task.CompletedTask;
    }

    protected override Task AdvanceEmailOutboxTimeAsync(TimeSpan offset)
    {
        _timeProvider.Advance(offset);
        return Task.CompletedTask;
    }

    protected override Task<int> ProcessEmailOutboxBatchAsync(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailOutboxDispatcher>().ProcessBatchAsync();
    }

    protected override async Task<EmailOutboxRowState> ReadSingleEmailOutboxRowAsync()
    {
        await using var connection = new SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT text_body,
                   html_body,
                   sensitivity,
                   body_protection,
                   attempt_count,
                   last_error
            FROM ashlar_email_outbox
            ORDER BY created_at, id
            LIMIT 1;
            """;
        await using var reader = await command.ExecuteReaderAsync();
        Assert.That(await reader.ReadAsync(), Is.True);
        return new EmailOutboxRowState(
            reader.GetNullableString("text_body"),
            reader.GetNullableString("html_body"),
            reader.GetString(reader.GetOrdinal("sensitivity")),
            reader.GetString(reader.GetOrdinal("body_protection")),
            reader.GetInt32(reader.GetOrdinal("attempt_count")),
            reader.GetNullableString("last_error"));
    }

    protected override async Task SeedEmailOutboxRowAsync(SeedEmailOutboxRow row)
    {
        await InsertEmailOutboxRowAsync(row);
    }

    protected override async Task SeedUnknownBodyProtectionEmailOutboxRowAsync(SeedEmailOutboxRow row)
    {
        await using var connection = new SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await SetIgnoreCheckConstraintsAsync(connection, ignoreCheckConstraints: true);
        try
        {
            await InsertEmailOutboxRowAsync(connection, row);
        }
        finally
        {
            await SetIgnoreCheckConstraintsAsync(connection, ignoreCheckConstraints: false);
        }
    }

    private async Task InsertEmailOutboxRowAsync(SeedEmailOutboxRow row)
    {
        await using var connection = new SqliteConnection(_database!.ConnectionString);
        await connection.OpenAsync();
        await InsertEmailOutboxRowAsync(connection, row);
    }

    private static async Task InsertEmailOutboxRowAsync(SqliteConnection connection, SeedEmailOutboxRow row)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_email_outbox (
                id, to_address, subject, text_body, html_body, sensitivity, body_protection,
                created_at, available_at, failed_at, locked_by, locked_until, attempt_count, last_error
            ) VALUES (
                $id, $toAddress, $subject, $textBody, $htmlBody, $sensitivity, $bodyProtection,
                $createdAt, $availableAt, $failedAt, $lockedBy, $lockedUntil, $attemptCount, $lastError
            );
            """;
        BindEmailOutboxRow(command, row);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task SetIgnoreCheckConstraintsAsync(SqliteConnection connection, bool ignoreCheckConstraints)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA ignore_check_constraints = {(ignoreCheckConstraints ? "ON" : "OFF")};";
        await command.ExecuteNonQueryAsync();
    }

    private static void BindEmailOutboxRow(SqliteCommand command, SeedEmailOutboxRow row)
    {
        command.AddGuidParameter("$id", row.Id);
        command.AddParameter("$toAddress", row.ToAddress);
        command.AddParameter("$subject", row.Subject);
        command.AddParameter("$textBody", row.TextBody);
        command.AddParameter("$htmlBody", row.HtmlBody);
        command.AddParameter("$sensitivity", row.Sensitivity);
        command.AddParameter("$bodyProtection", row.BodyProtection);
        command.AddDateTimeOffsetParameter("$createdAt", row.CreatedAt);
        command.AddDateTimeOffsetParameter("$availableAt", row.AvailableAt);
        command.AddParameter("$failedAt", row.FailedAt?.ToString("O", CultureInfo.InvariantCulture));
        command.AddParameter("$lockedBy", row.LockedBy);
        command.AddParameter("$lockedUntil", row.LockedUntil?.ToString("O", CultureInfo.InvariantCulture));
        command.AddParameter("$attemptCount", row.AttemptCount);
        command.AddParameter("$lastError", row.LastError);
    }
}
