using System.Security.Cryptography;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security.Hashing;
using Moq;

namespace Ashlar.Tests.Identity;

public class TotpProviderTests
{
    private TotpProvider _provider;

    [SetUp]
    public void SetUp()
    {
        _provider = new TotpProvider();
    }

    [Test]
    public async Task AuthenticateAsyncWithNullCredentialShouldReturnFailed()
    {
        var assertion = new TotpAssertion("123456");
        var result = await _provider.AuthenticateAsync(assertion, null);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithInvalidCodeShouldReturnFailed()
    {
        var secret = new byte[20];
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = Convert.ToBase64String(secret) 
        };
        var assertion = new TotpAssertion("000000"); // Highly unlikely to match dummy or real

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithMalformedSecretShouldReturnFailed()
    {
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = "not-base64!" 
        };
        var assertion = new TotpAssertion("123456");

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard requires HMAC-SHA1")]
    public async Task AuthenticateAsyncWith8DigitConfigShouldVerify()
    {
        var options = new TotpOptions { Digits = 8 };
        var provider = new TotpProvider(options);
        
        var secret = new byte[20];
        var credential = new UserCredential 
        { 
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = Convert.ToBase64String(secret) 
        };

        // Generate valid 8-digit code
        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        using var hmac = new HMACSHA1(secret);
        var bytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        var hash = hmac.ComputeHash(bytes);
        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);
        var code = (binary % 100000000).ToString("D8", System.Globalization.CultureInfo.InvariantCulture);

        var assertion = new TotpAssertion(code);

        var result = await provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public void TotpOptionsShouldThrowOnInvalidDigits()
    {
        var options = new TotpOptions();
        Assert.Throws<ArgumentException>(() => options.Digits = 7);
        Assert.Throws<ArgumentException>(() => options.Digits = 4);
        Assert.DoesNotThrow(() => options.Digits = 8);
        Assert.DoesNotThrow(() => options.Digits = 6);
    }

    [Test]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard requires HMAC-SHA1")]
    public async Task AuthenticateAsyncWithCustomPeriodShouldVerify()
    {
        var options = new TotpOptions { Period = 60 };
        var provider = new TotpProvider(options);

        var secret = new byte[20];
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = Convert.ToBase64String(secret)
        };

        // Generate valid code for 60s period
        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        using var hmac = new HMACSHA1(secret);
        var bytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        var hash = hmac.ComputeHash(bytes);
        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);
        var code = (binary % 1000000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);

        var assertion = new TotpAssertion(code);

        var result = await provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard requires HMAC-SHA1")]
    public async Task AuthenticateAsyncWithZeroPeriodShouldNotThrowAndVerifyWithDefaultMinPeriod()
    {
        var options = new TotpOptions { Period = 0 }; // Invalid period
        var provider = new TotpProvider(options);

        var secret = new byte[20];
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = Convert.ToBase64String(secret)
        };

        // If period clamps to 1, we generate code for period 1
        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 1;
        using var hmac = new HMACSHA1(secret);
        var bytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        var hash = hmac.ComputeHash(bytes);
        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);
        var code = (binary % 1000000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);

        var assertion = new TotpAssertion(code);

        // Should not throw DivideByZeroException
        var result = await provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public async Task AuthenticateAsyncShouldPreventReplayOfSameCode()
    {
        var secret = new byte[20];
        RandomNumberGenerator.Fill(secret);
        var secretBase64 = Convert.ToBase64String(secret);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = secretBase64
        };

        // Generate a valid code for current iteration
        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = CalculateTotp(secret, iteration, HashAlgorithmName.SHA1);
        var assertion = new TotpAssertion(code);

        // First attempt - Success
        var result1 = await _provider.AuthenticateAsync(assertion, credential);
        Assert.That(result1.Result, Is.EqualTo(PasswordVerificationResult.Success));
        Assert.That(result1.NewMetadata, Is.Not.Null);

        // Update credential with metadata from first success
        credential.Metadata = result1.NewMetadata;

        // Second attempt with same code - Failure (Replay)
        var result2 = await _provider.AuthenticateAsync(assertion, credential);
        Assert.That(result2.Result, Is.EqualTo(PasswordVerificationResult.Failed), "Code reuse should be blocked by replay protection.");
    }

    [Test]
    public async Task AuthenticateAsyncShouldPersistAlgorithmInMetadata()
    {
        var secret = new byte[32]; // SHA256 key
        RandomNumberGenerator.Fill(secret);
        var secretBase64 = Convert.ToBase64String(secret);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Totp,
            ProviderName = ProviderType.Totp.Value,
            ProviderKey = ProviderType.Totp.Value,
            CredentialValue = secretBase64
        };

        long iteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = CalculateTotp(secret, iteration, HashAlgorithmName.SHA256);
        var assertion = new TotpAssertion(code);

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
        Assert.That(result.NewMetadata, Does.Contain("SHA256"));
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard requires HMAC-SHA1")]
    private static string CalculateTotp(byte[] secret, long iteration, HashAlgorithmName algorithm)
    {
        byte[] iterationBytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(iterationBytes);

        using var hmac = algorithm == HashAlgorithmName.SHA256
            ? (HMAC)new HMACSHA256(secret)
            : new HMACSHA1(secret);

        byte[] hash = hmac.ComputeHash(iterationBytes);

        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);

        int password = binary % (int)Math.Pow(10, 6); // Default 6 digits
        return password.ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}