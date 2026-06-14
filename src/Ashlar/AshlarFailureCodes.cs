namespace Ashlar;

/// <summary>
/// Known stable Ashlar failure codes.
/// </summary>
public static class AshlarFailureCodes
{
    /// <summary>Generic validation failure.</summary>
    public const string ValidationErrorValue = "validation_error";
    /// <summary>Configured metadata is invalid.</summary>
    public const string InvalidMetadataValue = "invalid_metadata";
    /// <summary>Metadata JSON could not be parsed.</summary>
    public const string InvalidMetadataJsonValue = "invalid_metadata_json";
    /// <summary>Metadata format is invalid.</summary>
    public const string InvalidMetadataFormatValue = "invalid_metadata_format";
    /// <summary>Metadata exceeds the configured maximum length.</summary>
    public const string MetadataTooLongValue = "metadata_too_long";
    /// <summary>The request is rate limited.</summary>
    public const string RateLimitedValue = "rate_limited";
    /// <summary>The rate limit was exceeded.</summary>
    public const string RateLimitExceededValue = "rate_limit_exceeded";
    /// <summary>The supplied callback URI is not allowed.</summary>
    public const string InvalidCallbackUriValue = "invalid_callback_uri";
    /// <summary>The user could not be found.</summary>
    public const string UserNotFoundValue = "user_not_found";
    /// <summary>The user could not be found or cannot currently sign in.</summary>
    public const string UserNotFoundOrUnavailableValue = "user_not_found_or_unavailable";
    /// <summary>The requested user already exists.</summary>
    public const string UserExistsValue = "user_exists";
    /// <summary>The token is empty.</summary>
    public const string EmptyTokenValue = "empty_token";
    /// <summary>The code is empty.</summary>
    public const string EmptyCodeValue = "empty_code";
    /// <summary>The code is invalid.</summary>
    public const string InvalidCodeValue = "invalid_code";
    /// <summary>The token is invalid or expired.</summary>
    public const string InvalidOrExpiredTokenValue = "invalid_or_expired_token";
    /// <summary>The token could not be consumed.</summary>
    public const string TokenConsumptionFailedValue = "token_consumption_failed";
    /// <summary>The token data is invalid.</summary>
    public const string InvalidTokenDataValue = "invalid_token_data";
    /// <summary>The requested provider is not supported.</summary>
    public const string ProviderUnsupportedValue = "provider_unsupported";
    /// <summary>The provider key is invalid.</summary>
    public const string InvalidProviderKeyValue = "invalid_provider_key";
    /// <summary>The credential already exists.</summary>
    public const string CredentialAlreadyExistsValue = "credential_already_exists";
    /// <summary>The credential was not found.</summary>
    public const string CredentialNotFoundValue = "credential_not_found";
    /// <summary>The credential is already linked to the same user.</summary>
    public const string AlreadyLinkedToSelfValue = "already_linked_to_self";
    /// <summary>The credential is already linked to another user.</summary>
    public const string AlreadyLinkedToOtherValue = "already_linked_to_other";
    /// <summary>The supplied secret is invalid.</summary>
    public const string InvalidSecretValue = "invalid_secret";
    /// <summary>The supplied secret format is invalid.</summary>
    public const string InvalidSecretFormatValue = "invalid_secret_format";
    /// <summary>The credential link operation failed.</summary>
    public const string LinkFailedValue = "link_failed";
    /// <summary>The code count is invalid.</summary>
    public const string InvalidCodeCountValue = "invalid_code_count";
    /// <summary>The configuration is invalid.</summary>
    public const string InvalidConfigurationValue = "invalid_configuration";
    /// <summary>The expiry is invalid.</summary>
    public const string InvalidExpiryValue = "invalid_expiry";
    /// <summary>The email is already in use.</summary>
    public const string EmailAlreadyInUseValue = "email_already_in_use";
    /// <summary>The email matches the current email.</summary>
    public const string SameEmailValue = "same_email";
    /// <summary>The invitation is invalid.</summary>
    public const string InvalidInvitationValue = "invalid_invitation";
    /// <summary>The invitation was not found.</summary>
    public const string InvitationNotFoundValue = "invitation_not_found";
    /// <summary>The operation has already been initialized.</summary>
    public const string AlreadyInitializedValue = "already_initialized";
    /// <summary>The operation failed because of a concurrency conflict.</summary>
    public const string ConcurrencyConflictValue = "concurrency_conflict";
    /// <summary>The tenant scope does not match the referenced user's tenant.</summary>
    public const string TenantMismatchValue = "tenant_mismatch";
    /// <summary>The grant creation failed.</summary>
    public const string GrantCreationFailedValue = "grant_creation_failed";
    /// <summary>The authorization grant shape is invalid.</summary>
    public const string InvalidGrantShapeValue = "invalid_grant_shape";
    /// <summary>The authorization scope shape is invalid.</summary>
    public const string InvalidScopeShapeValue = "invalid_scope_shape";
    /// <summary>No MFA factors were specified.</summary>
    public const string NoFactorsSpecifiedValue = "no_factors_specified";
    /// <summary>The authentication handshake was not found.</summary>
    public const string HandshakeNotFoundValue = "handshake_not_found";
    /// <summary>The authentication handshake is revoked.</summary>
    public const string HandshakeRevokedValue = "handshake_revoked";
    /// <summary>The authentication handshake is already completed.</summary>
    public const string HandshakeAlreadyCompletedValue = "handshake_already_completed";
    /// <summary>The authentication handshake is expired.</summary>
    public const string HandshakeExpiredValue = "handshake_expired";
    /// <summary>The authentication factor type is invalid.</summary>
    public const string InvalidFactorTypeValue = "invalid_factor_type";
    /// <summary>The authentication factor is already verified.</summary>
    public const string FactorAlreadyVerifiedValue = "factor_already_verified";
    /// <summary>The passkey challenge was not found, expired, or already consumed.</summary>
    public const string PasskeyChallengeInvalidValue = "passkey_challenge_invalid";
    /// <summary>The passkey ceremony response failed WebAuthn validation.</summary>
    public const string PasskeyValidationFailedValue = "passkey_validation_failed";
    /// <summary>The passkey credential was not found or is not active.</summary>
    public const string PasskeyCredentialNotFoundValue = "passkey_credential_not_found";
    /// <summary>The session was not found or is inactive.</summary>
    public const string SessionNotFoundOrInactiveValue = "session_not_found_or_inactive";
    /// <summary>The session was not found.</summary>
    public const string SessionNotFoundValue = "session_not_found";
    /// <summary>The security event was not found.</summary>
    public const string SecurityEventNotFoundValue = "security_event_not_found";
    /// <summary>Additional verification is required.</summary>
    public const string StepUpRequiredValue = "step_up_required";
    /// <summary>Additional verification is no longer fresh.</summary>
    public const string StepUpExpiredValue = "step_up_expired";
    /// <summary>The additional verification provider is not allowed.</summary>
    public const string StepUpProviderNotAllowedValue = "step_up_provider_not_allowed";
    /// <summary>The additional verification factor is not allowed.</summary>
    public const string StepUpFactorNotAllowedValue = "step_up_factor_not_allowed";
    /// <summary>The user has reached the remembered MFA device limit.</summary>
    public const string RememberedMfaDeviceLimitExceededValue = "remembered_mfa_device_limit_exceeded";
    /// <summary>Generic validation failure.</summary>
    public static readonly AshlarFailureCode ValidationError = new(ValidationErrorValue);
    /// <summary>Configured metadata is invalid.</summary>
    public static readonly AshlarFailureCode InvalidMetadata = new(InvalidMetadataValue);
    /// <summary>Metadata JSON could not be parsed.</summary>
    public static readonly AshlarFailureCode InvalidMetadataJson = new(InvalidMetadataJsonValue);
    /// <summary>Metadata format is invalid.</summary>
    public static readonly AshlarFailureCode InvalidMetadataFormat = new(InvalidMetadataFormatValue);
    /// <summary>Metadata exceeds the configured maximum length.</summary>
    public static readonly AshlarFailureCode MetadataTooLong = new(MetadataTooLongValue);
    /// <summary>The request is rate limited.</summary>
    public static readonly AshlarFailureCode RateLimited = new(RateLimitedValue);
    /// <summary>The rate limit was exceeded.</summary>
    public static readonly AshlarFailureCode RateLimitExceeded = new(RateLimitExceededValue);
    /// <summary>The supplied callback URI is not allowed.</summary>
    public static readonly AshlarFailureCode InvalidCallbackUri = new(InvalidCallbackUriValue);
    /// <summary>The user could not be found.</summary>
    public static readonly AshlarFailureCode UserNotFound = new(UserNotFoundValue);
    /// <summary>The user could not be found or cannot currently sign in.</summary>
    public static readonly AshlarFailureCode UserNotFoundOrUnavailable = new(UserNotFoundOrUnavailableValue);
    /// <summary>The requested user already exists.</summary>
    public static readonly AshlarFailureCode UserExists = new(UserExistsValue);
    /// <summary>The token is empty.</summary>
    public static readonly AshlarFailureCode EmptyToken = new(EmptyTokenValue);
    /// <summary>The code is empty.</summary>
    public static readonly AshlarFailureCode EmptyCode = new(EmptyCodeValue);
    /// <summary>The code is invalid.</summary>
    public static readonly AshlarFailureCode InvalidCode = new(InvalidCodeValue);
    /// <summary>The token is invalid or expired.</summary>
    public static readonly AshlarFailureCode InvalidOrExpiredToken = new(InvalidOrExpiredTokenValue);
    /// <summary>The token could not be consumed.</summary>
    public static readonly AshlarFailureCode TokenConsumptionFailed = new(TokenConsumptionFailedValue);
    /// <summary>The token data is invalid.</summary>
    public static readonly AshlarFailureCode InvalidTokenData = new(InvalidTokenDataValue);
    /// <summary>The requested provider is not supported.</summary>
    public static readonly AshlarFailureCode ProviderUnsupported = new(ProviderUnsupportedValue);
    /// <summary>The provider key is invalid.</summary>
    public static readonly AshlarFailureCode InvalidProviderKey = new(InvalidProviderKeyValue);
    /// <summary>The credential already exists.</summary>
    public static readonly AshlarFailureCode CredentialAlreadyExists = new(CredentialAlreadyExistsValue);
    /// <summary>The credential was not found.</summary>
    public static readonly AshlarFailureCode CredentialNotFound = new(CredentialNotFoundValue);
    /// <summary>The credential is already linked to the same user.</summary>
    public static readonly AshlarFailureCode AlreadyLinkedToSelf = new(AlreadyLinkedToSelfValue);
    /// <summary>The credential is already linked to another user.</summary>
    public static readonly AshlarFailureCode AlreadyLinkedToOther = new(AlreadyLinkedToOtherValue);
    /// <summary>The supplied secret is invalid.</summary>
    public static readonly AshlarFailureCode InvalidSecret = new(InvalidSecretValue);
    /// <summary>The supplied secret format is invalid.</summary>
    public static readonly AshlarFailureCode InvalidSecretFormat = new(InvalidSecretFormatValue);
    /// <summary>The credential link operation failed.</summary>
    public static readonly AshlarFailureCode LinkFailed = new(LinkFailedValue);
    /// <summary>The code count is invalid.</summary>
    public static readonly AshlarFailureCode InvalidCodeCount = new(InvalidCodeCountValue);
    /// <summary>The configuration is invalid.</summary>
    public static readonly AshlarFailureCode InvalidConfiguration = new(InvalidConfigurationValue);
    /// <summary>The expiry is invalid.</summary>
    public static readonly AshlarFailureCode InvalidExpiry = new(InvalidExpiryValue);
    /// <summary>The email is already in use.</summary>
    public static readonly AshlarFailureCode EmailAlreadyInUse = new(EmailAlreadyInUseValue);
    /// <summary>The email matches the current email.</summary>
    public static readonly AshlarFailureCode SameEmail = new(SameEmailValue);
    /// <summary>The invitation is invalid.</summary>
    public static readonly AshlarFailureCode InvalidInvitation = new(InvalidInvitationValue);
    /// <summary>The invitation was not found.</summary>
    public static readonly AshlarFailureCode InvitationNotFound = new(InvitationNotFoundValue);
    /// <summary>The operation has already been initialized.</summary>
    public static readonly AshlarFailureCode AlreadyInitialized = new(AlreadyInitializedValue);
    /// <summary>The operation failed because of a concurrency conflict.</summary>
    public static readonly AshlarFailureCode ConcurrencyConflict = new(ConcurrencyConflictValue);
    /// <summary>The tenant scope does not match the referenced user's tenant.</summary>
    public static readonly AshlarFailureCode TenantMismatch = new(TenantMismatchValue);
    /// <summary>The grant creation failed.</summary>
    public static readonly AshlarFailureCode GrantCreationFailed = new(GrantCreationFailedValue);
    /// <summary>The authorization grant shape is invalid.</summary>
    public static readonly AshlarFailureCode InvalidGrantShape = new(InvalidGrantShapeValue);
    /// <summary>The authorization scope shape is invalid.</summary>
    public static readonly AshlarFailureCode InvalidScopeShape = new(InvalidScopeShapeValue);
    /// <summary>No MFA factors were specified.</summary>
    public static readonly AshlarFailureCode NoFactorsSpecified = new(NoFactorsSpecifiedValue);
    /// <summary>The authentication handshake was not found.</summary>
    public static readonly AshlarFailureCode HandshakeNotFound = new(HandshakeNotFoundValue);
    /// <summary>The authentication handshake is revoked.</summary>
    public static readonly AshlarFailureCode HandshakeRevoked = new(HandshakeRevokedValue);
    /// <summary>The authentication handshake is already completed.</summary>
    public static readonly AshlarFailureCode HandshakeAlreadyCompleted = new(HandshakeAlreadyCompletedValue);
    /// <summary>The authentication handshake is expired.</summary>
    public static readonly AshlarFailureCode HandshakeExpired = new(HandshakeExpiredValue);
    /// <summary>The authentication factor type is invalid.</summary>
    public static readonly AshlarFailureCode InvalidFactorType = new(InvalidFactorTypeValue);
    /// <summary>The authentication factor is already verified.</summary>
    public static readonly AshlarFailureCode FactorAlreadyVerified = new(FactorAlreadyVerifiedValue);
    /// <summary>The passkey challenge was not found, expired, or already consumed.</summary>
    public static readonly AshlarFailureCode PasskeyChallengeInvalid = new(PasskeyChallengeInvalidValue);
    /// <summary>The passkey ceremony response failed WebAuthn validation.</summary>
    public static readonly AshlarFailureCode PasskeyValidationFailed = new(PasskeyValidationFailedValue);
    /// <summary>The passkey credential was not found or is not active.</summary>
    public static readonly AshlarFailureCode PasskeyCredentialNotFound = new(PasskeyCredentialNotFoundValue);
    /// <summary>The session was not found or is inactive.</summary>
    public static readonly AshlarFailureCode SessionNotFoundOrInactive = new(SessionNotFoundOrInactiveValue);
    /// <summary>The session was not found.</summary>
    public static readonly AshlarFailureCode SessionNotFound = new(SessionNotFoundValue);
    /// <summary>The security event was not found.</summary>
    public static readonly AshlarFailureCode SecurityEventNotFound = new(SecurityEventNotFoundValue);
    /// <summary>Additional verification is required.</summary>
    public static readonly AshlarFailureCode StepUpRequired = new(StepUpRequiredValue);
    /// <summary>Additional verification is no longer fresh.</summary>
    public static readonly AshlarFailureCode StepUpExpired = new(StepUpExpiredValue);
    /// <summary>The additional verification provider is not allowed.</summary>
    public static readonly AshlarFailureCode StepUpProviderNotAllowed = new(StepUpProviderNotAllowedValue);
    /// <summary>The additional verification factor is not allowed.</summary>
    public static readonly AshlarFailureCode StepUpFactorNotAllowed = new(StepUpFactorNotAllowedValue);
    /// <summary>The user has reached the remembered MFA device limit.</summary>
    public static readonly AshlarFailureCode RememberedMfaDeviceLimitExceeded = new(RememberedMfaDeviceLimitExceededValue);
}
