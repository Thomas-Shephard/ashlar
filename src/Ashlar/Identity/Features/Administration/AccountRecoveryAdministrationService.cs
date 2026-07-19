using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements read-only administrator account recovery option summaries.
/// </summary>
/// <param name="userAdministrationService">Service used to retrieve safe user and security posture details.</param>
/// <param name="rememberedMfaDeviceReader">Optional remembered MFA device reader used to preview MFA reset impact.</param>
public sealed class AccountRecoveryAdministrationService(
    IUserAdministrationService userAdministrationService,
    IRememberedMfaDeviceReader? rememberedMfaDeviceReader = null)
    : IAccountRecoveryAdministrationService
{
    internal const string LastPrimarySignInMethodWarningCode = "last_primary_sign_in_method";

    private readonly IUserAdministrationService _userAdministrationService = userAdministrationService ?? throw new ArgumentNullException(nameof(userAdministrationService));
    private readonly IRememberedMfaDeviceReader? _rememberedMfaDeviceReader = rememberedMfaDeviceReader;

    /// <inheritdoc />
    public async Task<Result<AccountRecoveryOptions>> GetAccountRecoveryOptionsAsync(
        AccountRecoveryOptionsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var detailResult = await _userAdministrationService.GetUserDetailAsync(
            new UserAdministrationDetailRequest(
                request.UserId,
                request.Tenant,
                request.IncludeAllTenants,
                request.RecentSecurityEventWindow,
                request.Actor),
            cancellationToken);
        if (!detailResult.Succeeded || detailResult.Value == null)
        {
            return Result.Failure<AccountRecoveryOptions>(detailResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.UserNotFound));
        }

        var rememberedMfaDeviceCount = await CountRememberedMfaDevicesAsync(request, cancellationToken);
        var detail = detailResult.Value;
        var posture = detail.SecurityPosture;
        var activeCredentials = posture.CredentialInventory
            .Where(credential => credential.Status == CredentialStatus.Active)
            .ToArray();
        var primaryCredentials = posture.PrimaryCredentials
            .Where(credential => credential.Status == CredentialStatus.Active && credential.IsAvailable)
            .ToArray();
        var revocableProviderOptions = activeCredentials
            .Where(credential => credential.IsRevocable)
            .GroupBy(credential => credential.Provider)
            .Select(group => CreateProviderOption(group, primaryCredentials))
            .OrderBy(option => option.Provider.Type.Value, StringComparer.Ordinal)
            .ThenBy(option => option.Provider.Name, StringComparer.Ordinal)
            .ToArray();
        var warnings = revocableProviderOptions
            .Where(option => option.WouldRemoveLastPrimarySignInMethod)
            .Select(option => new AccountRecoveryWarning(
                LastPrimarySignInMethodWarningCode,
                "Revoking this provider may remove the last primary sign-in method.",
                option.Provider))
            .ToArray();

        return Result.Success(new AccountRecoveryOptions(
            detail,
            new AccountRecoveryActionOptions(
                WouldResetMfa: rememberedMfaDeviceCount > 0 || activeCredentials.Any(credential => credential.IsResettable),
                WouldRevokeSessions: posture.ActiveSessionCount > 0,
                revocableProviderOptions,
                warnings)));
    }

    private async Task<int> CountRememberedMfaDevicesAsync(AccountRecoveryOptionsRequest request, CancellationToken cancellationToken)
    {
        if (_rememberedMfaDeviceReader == null)
        {
            return 0;
        }

        var devices = await _rememberedMfaDeviceReader.ListAsync(
            request.UserId,
            new ListRememberedMfaDevicesRequest
            {
                Tenant = request.Tenant,
                IncludeAllTenants = request.IncludeAllTenants,
                ActiveOnly = true
            },
            cancellationToken);
        return devices.Count;
    }

    private static AccountRecoveryProviderOption CreateProviderOption(
        IGrouping<AuthenticationProviderKey, CredentialPostureItem> group,
        CredentialPostureItem[] primaryCredentials)
    {
        var credentials = group.ToArray();
        var primaryCredentialCount = credentials.Count(credential => credential.IsPrimaryCredential);

        return new AccountRecoveryProviderOption(
            group.Key,
            SelectDisplayName(credentials, group.Key),
            credentials.Length,
            primaryCredentialCount,
            credentials.Count(credential => credential.IsAdditionalVerificationFactor),
            primaryCredentialCount > 0
                && primaryCredentials.Length > 0
                && primaryCredentials.All(credential => credential.Provider == group.Key));
    }

    private static string SelectDisplayName(IEnumerable<CredentialPostureItem> credentials, AuthenticationProviderKey provider)
    {
        var displayName = credentials
            .Select(credential => credential.DisplayName)
            .Where(displayName => !string.IsNullOrWhiteSpace(displayName))
            .Order(StringComparer.Ordinal)
            .FirstOrDefault();

        return displayName ?? provider.Name;
    }

    private static bool TryValidateRequest(AccountRecoveryOptionsRequest request, [NotNullWhen(false)] out Result<AccountRecoveryOptions>? failure)
    {
        try
        {
            AccountRecoveryOptionsRequest.ThrowIfInvalid(request);
            failure = null;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AccountRecoveryOptions>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
