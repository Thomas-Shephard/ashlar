// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Microsoft.Extensions.DependencyInjection.Extensions;

internal static class AshlarProviderServiceCollection
{
    internal static IServiceCollection TryAddProviderScoped<TService, TImplementation>(IServiceCollection services)
        where TService : class
        where TImplementation : class, TService
    {
        services.TryAddScoped<AshlarProviderService<TService>>(provider =>
            new AshlarProviderService<TService>(ActivatorUtilities.CreateInstance<TImplementation>(provider)));
        return services;
    }

    internal static T GetRequiredAshlarProviderService<T>(this IServiceProvider provider) where T : class =>
        provider.GetRequiredService<AshlarProviderService<T>>().Value;

    internal static object GetRequiredAshlarProviderService(this IServiceProvider provider, Type serviceType) =>
        ((IAshlarProviderService)provider.GetRequiredService(typeof(AshlarProviderService<>).MakeGenericType(serviceType))).Value;

    internal static T? GetAshlarProviderService<T>(this IServiceProvider provider) where T : class =>
        provider.GetService<AshlarProviderService<T>>()?.Value;
}

internal interface IAshlarProviderService
{
    object Value { get; }
}

internal sealed class AshlarProviderService<T> : IAshlarProviderService, IDisposable, IAsyncDisposable where T : class
{
    private readonly bool _ownsValue;

    internal AshlarProviderService(T value, bool ownsValue = true)
    {
        Value = value ?? throw new ArgumentNullException(nameof(value));
        _ownsValue = ownsValue;
    }

    internal T Value { get; }
    object IAshlarProviderService.Value => Value;

    public void Dispose()
    {
        if (!_ownsValue) return;
        if (Value is IDisposable disposable) disposable.Dispose();
        else if (Value is IAsyncDisposable asyncDisposable) asyncDisposable.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    public ValueTask DisposeAsync() => !_ownsValue
        ? ValueTask.CompletedTask
        : Value switch
        {
            IAsyncDisposable disposable => disposable.DisposeAsync(),
            IDisposable disposable => DisposeAsync(disposable),
            _ => ValueTask.CompletedTask
        };

    private static ValueTask DisposeAsync(IDisposable disposable)
    {
        disposable.Dispose();
        return ValueTask.CompletedTask;
    }
}
