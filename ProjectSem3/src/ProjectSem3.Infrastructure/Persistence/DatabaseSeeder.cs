using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ProjectSem3.Domain.Constants;
using ProjectSem3.Infrastructure.Identity;

namespace ProjectSem3.Infrastructure.Persistence;

public sealed class DatabaseSeeder(
    ApplicationDbContext dbContext,
    RoleManager<IdentityRole<Guid>> roleManager,
    UserManager<ApplicationUser> userManager,
    IConfiguration configuration,
    TimeProvider timeProvider,
    ILogger<DatabaseSeeder> logger)
{
    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        await dbContext.Database.MigrateAsync(cancellationToken);

        foreach (var roleName in Roles.All)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
                EnsureSucceeded(await roleManager.CreateAsync(new IdentityRole<Guid>(roleName)));
        }

        await SetPermissionsAsync(Roles.Admin, Permissions.All);
        await SetPermissionsAsync(Roles.Staff, [Permissions.UsersView]);
        await SetPermissionsAsync(Roles.User, []);

        var email = configuration["SeedAdmin:Email"];
        var password = configuration["SeedAdmin:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            logger.LogWarning("Không tạo tài khoản Admin ban đầu vì SeedAdmin chưa được cấu hình.");
            return;
        }

        var admin = await userManager.FindByEmailAsync(email);
        if (admin is null)
        {
            admin = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                Email = email.Trim(),
                UserName = email.Trim(),
                EmailConfirmed = true,
                IsActive = true,
                CreatedAtUtc = timeProvider.GetUtcNow().UtcDateTime
            };
            EnsureSucceeded(await userManager.CreateAsync(admin, password));
        }

        if (!await userManager.IsInRoleAsync(admin, Roles.Admin))
            EnsureSucceeded(await userManager.AddToRoleAsync(admin, Roles.Admin));
    }

    private async Task SetPermissionsAsync(string roleName, IReadOnlyCollection<string> permissions)
    {
        var role = await roleManager.FindByNameAsync(roleName)
            ?? throw new InvalidOperationException($"Không tìm thấy role {roleName}.");
        var currentClaims = (await roleManager.GetClaimsAsync(role))
            .Where(x => x.Type == Permissions.ClaimType)
            .ToArray();

        foreach (var claim in currentClaims.Where(x => !permissions.Contains(x.Value)))
            EnsureSucceeded(await roleManager.RemoveClaimAsync(role, claim));

        foreach (var permission in permissions.Except(currentClaims.Select(x => x.Value)))
            EnsureSucceeded(await roleManager.AddClaimAsync(role, new Claim(Permissions.ClaimType, permission)));
    }

    private static void EnsureSucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(" ", result.Errors.Select(x => x.Description)));
    }
}
