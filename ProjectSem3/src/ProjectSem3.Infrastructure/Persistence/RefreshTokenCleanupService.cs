using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ProjectSem3.Infrastructure.Persistence;

public sealed class RefreshTokenCleanupService(
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    ILogger<RefreshTokenCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(6), timeProvider);
        while (!stoppingToken.IsCancellationRequested)
        {
            await CleanupAsync(stoppingToken);
            await timer.WaitForNextTickAsync(stoppingToken);
        }
    }

    private async Task CleanupAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var cutoff = timeProvider.GetUtcNow().UtcDateTime.AddDays(-30);
            var deleted = await dbContext.RefreshTokens
                .Where(x => x.ExpiresAtUtc < cutoff || (x.RevokedAtUtc != null && x.RevokedAtUtc < cutoff))
                .ExecuteDeleteAsync(cancellationToken);
            if (deleted > 0)
                logger.LogInformation("Deleted {Count} expired refresh tokens.", deleted);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Refresh token cleanup failed.");
        }
    }
}
