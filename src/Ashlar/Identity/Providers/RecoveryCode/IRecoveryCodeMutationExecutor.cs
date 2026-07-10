namespace Ashlar.Identity.Providers.RecoveryCode;

internal interface IRecoveryCodeMutationExecutor
{
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(
        Guid userId,
        RecoveryCodeGenerationExecutionRequest request,
        CancellationToken cancellationToken = default);

    Task<Result<int>> RevokeRecoveryCodesAsync(
        Guid userId,
        RevokeRecoveryCodesExecutionRequest request,
        CancellationToken cancellationToken = default);
}
