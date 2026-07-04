using Ashlar.Security.Hashing;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Implements an authentication provider that verifies recovery codes as backup additional-verification factors.
/// </summary>
public sealed class RecoveryCodeAuthenticationProvider : IBackupAuthenticationFactorProvider, IAuthenticationUserResolver, IAuthenticationCredentialResolver
{
    private const int IdCodeLength = 5;
    private const int IdSecretSeparatorLength = 1;
    private const int ExtraSubmittedFormattingCharacters = 32;

    private readonly PasswordHasherSelector _hasherSelector;
    private readonly RecoveryCodeOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="hasherSelector">Hashing component used to verify submitted recovery-code secrets.</param>
    /// <param name="options">Recovery-code provider configuration.</param>
    /// <param name="timeProvider">Clock used to evaluate credential availability, or <see langword="null" /> to use the system clock.</param>
    public RecoveryCodeAuthenticationProvider(
        PasswordHasherSelector hasherSelector,
        IOptions<RecoveryCodeOptions> options,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(hasherSelector);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Value);

        _hasherSelector = hasherSelector;
        _options = options.Value;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Derives the provider key from the recovery-code id segment.
    /// </summary>
    public AuthenticationProviderKey Key => _options.ProviderKey;

    /// <summary>
    /// Gets a value indicating that recovery-code credentials are stored as hashes.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Gets the typical persisted hash payload length for recovery-code credentials.
    /// </summary>
    public int TypicalCredentialLength => 128; // Hashed password length

    /// <summary>
    /// Gets the backup factor family represented by recovery codes.
    /// </summary>
    public string FactorType => AuthenticationFactorTypes.RecoveryCode;

    /// <summary>
    /// Determines whether recovery codes directly satisfy a pending recovery-code factor.
    /// </summary>
    /// <param name="factorType">Additional-verification factor family required by the pending challenge.</param>
    /// <returns><see langword="true" /> when the pending challenge explicitly requires recovery-code verification.</returns>
    public bool CanSatisfyFactor(string factorType) => AuthenticationFactorTypes.Matches(FactorType, factorType);

    /// <summary>
    /// Determines whether a recovery code may be used as backup for a pending additional-verification factor.
    /// </summary>
    /// <param name="requiredFactorType">Additional-verification factor family required by the pending challenge.</param>
    /// <returns><see langword="true" /> when the challenge names any factor family; recovery codes intentionally act as universal backup factors.</returns>
    public bool CanSatisfyBackupFactor(string requiredFactorType) => !string.IsNullOrWhiteSpace(requiredFactorType);

    /// <summary>
    /// Derives the stored recovery-code key from the submitted code's id segment.
    /// </summary>
    /// <param name="assertion">Recovery-code assertion associated with the lookup.</param>
    /// <param name="userId">User whose recovery-code credentials are being resolved.</param>
    /// <returns>The deterministic recovery-code storage key when the submitted code contains an id segment; otherwise, an empty string.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        if (assertion is not RecoveryCodeAssertion recoveryCodeAssertion)
        {
            return string.Empty;
        }

        return TryParseSubmittedCode(userId, recoveryCodeAssertion, out var providerKey, out _, out _)
            ? providerKey
            : string.Empty;
    }

    /// <summary>
    /// Hashes a raw recovery-code secret before persistence.
    /// </summary>
    /// <param name="assertion">Recovery-code assertion associated with the credential.</param>
    /// <param name="rawValue">Raw recovery-code secret. Do not log this value.</param>
    /// <returns>Encoded hash payload for storage, or <see langword="null" /> when no raw value was supplied.</returns>
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        var hashed = PasswordCredentialHashing.HashToBase64(_hasherSelector, rawValue);
        return hashed;
    }

    /// <summary>
    /// Resolves a user by the email in the authentication context.
    /// </summary>
    /// <param name="assertion">Recovery-code assertion supplied to the authentication pipeline.</param>
    /// <param name="context">Authentication context containing the email address and tenant scope used by normalized repository lookup.</param>
    /// <param name="repository">User repository used to resolve the account.</param>
    /// <param name="cancellationToken">Token for aborting lookup work.</param>
    /// <returns>The matching user, or <see langword="null" /> when the assertion or email cannot resolve an account.</returns>
    public Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IUserRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (assertion is not RecoveryCodeAssertion)
        {
            return Task.FromResult<IUser?>(null);
        }

        var email = context.Email;
        if (context.UserId.HasValue || string.IsNullOrWhiteSpace(email))
        {
            return Task.FromResult<IUser?>(null);
        }

        return repository.GetUserByEmailAsync(email, context.TenantId, cancellationToken);
    }

    /// <summary>
    /// Resolves and verifies the recovery-code credential for the submitted code.
    /// </summary>
    /// <param name="userId">User whose recovery-code credentials should be searched.</param>
    /// <param name="assertion">Recovery-code assertion containing the raw submitted code.</param>
    /// <param name="context">Authentication context for the current attempt.</param>
    /// <param name="repository">Credential repository used to load the candidate recovery-code credential.</param>
    /// <param name="cancellationToken">Token for aborting credential lookup work.</param>
    /// <returns>The matching credential when the code is valid and available; otherwise, <see langword="null" />.</returns>
    public async Task<UserCredential?> ResolveCredentialAsync(Guid userId, IAuthenticationAssertion assertion, AuthenticationContext? context, ICredentialRepository repository, CancellationToken cancellationToken = default)
    {
        if (assertion is not RecoveryCodeAssertion recoveryCodeAssertion)
        {
            return null;
        }

        if (!TryParseSubmittedCode(userId, recoveryCodeAssertion, out var providerKey, out var secretCode, out var normalizedCode))
        {
            if (recoveryCodeAssertion.Code.Length <= MaximumSubmittedCodeLength)
            {
                // Dummy verification to mitigate timing attacks
                _hasherSelector.VerifyPassword(normalizedCode, []);
            }

            return null;
        }

        var credential = await repository.GetCredentialForUserAsync(userId, Key.Type, Key.Name, providerKey, cancellationToken);

        if (credential == null || !credential.IsAvailable(_timeProvider.GetUtcNow()))
        {
            // Dummy verification to mitigate timing attacks
            _hasherSelector.VerifyPassword(normalizedCode, []);
            return null;
        }

        var hash = PasswordCredentialHashing.DecodeBase64(credential.CredentialValue);
        var result = _hasherSelector.VerifyPassword(secretCode, hash ?? []);

        if (result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessWithCredentialUpdate)
        {
            return credential;
        }

        return null;
    }

    private bool TryParseSubmittedCode(Guid userId, RecoveryCodeAssertion assertion, out string providerKey, out string secretCode, out string normalizedCode)
    {
        providerKey = string.Empty;
        secretCode = string.Empty;
        normalizedCode = assertion.Code.Replace(" ", "").ToUpperInvariant();

        if (assertion.Code.Length > MaximumSubmittedCodeLength)
        {
            return false;
        }

        var codeSpan = normalizedCode.AsSpan();
        var separatorIndex = codeSpan.IndexOf('-');
        if (separatorIndex <= 0 || separatorIndex == codeSpan.Length - 1)
        {
            return false;
        }

        providerKey = $"{userId:N}-{new string(codeSpan[..separatorIndex])}";
        secretCode = new string(codeSpan[(separatorIndex + 1)..]);
        return true;
    }

    private int MaximumSubmittedCodeLength =>
        IdCodeLength
        + IdSecretSeparatorLength
        + _options.CodeLength
        + ((_options.CodeLength - 1) / _options.GroupSize)
        + ExtraSubmittedFormattingCharacters;

    /// <summary>
    /// Marks a previously resolved recovery-code credential as successful and consumed.
    /// </summary>
    /// <param name="assertion">Recovery-code assertion supplied to the authentication pipeline.</param>
    /// <param name="credential">Credential returned from <see cref="ResolveCredentialAsync" />.</param>
    /// <param name="cancellationToken">Token for aborting authentication work.</param>
    /// <returns>Authentication status indicating success only when a matching credential was resolved.</returns>
    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not RecoveryCodeAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (credential == null)
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        // If we have a credential here, it means ResolveCredentialAsync found a match.
        return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
    }
}
