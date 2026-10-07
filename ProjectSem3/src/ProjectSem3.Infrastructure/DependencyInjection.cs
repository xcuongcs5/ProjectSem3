using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using ProjectSem3.Application.Abstractions;
using ProjectSem3.Domain.Constants;
using ProjectSem3.Infrastructure.Authentication;
using ProjectSem3.Infrastructure.Email;
using ProjectSem3.Infrastructure.Health;
using ProjectSem3.Infrastructure.Identity;
using ProjectSem3.Infrastructure.Persistence;

namespace ProjectSem3.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("Thiếu ConnectionStrings:DefaultConnection.");
        var jwt = configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>()
            ?? throw new InvalidOperationException("Thiếu cấu hình Jwt.");
        var email = configuration.GetSection(EmailOptions.SectionName).Get<EmailOptions>() ?? new EmailOptions();

        if (Encoding.UTF8.GetByteCount(jwt.SigningKey) < 32)
            throw new InvalidOperationException("Jwt:SigningKey phải có tối thiểu 32 byte và phải được lưu bằng User Secrets hoặc biến môi trường.");
        if (string.Equals(email.Mode, "Smtp", StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrWhiteSpace(email.Host) || string.IsNullOrWhiteSpace(email.FromEmail)))
            throw new InvalidOperationException("Email SMTP yêu cầu Email:Host và Email:FromEmail.");

        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));
        services.Configure<EmailOptions>(configuration.GetSection(EmailOptions.SectionName));
        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(
            connectionString,
            sql => sql.EnableRetryOnFailure(5, TimeSpan.FromSeconds(10), null)));
        services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.Password.RequiredLength = 10;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.SignIn.RequireConfirmedEmail = configuration.GetValue("Identity:RequireConfirmedEmail", true);
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddSignInManager()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwt.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwt.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(30),
                    RoleClaimType = System.Security.Claims.ClaimTypes.Role,
                    NameClaimType = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.UniqueName
                };
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var subject = context.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
                        var tokenStamp = context.Principal?.FindFirst("security_stamp")?.Value;
                        var manager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                        var user = Guid.TryParse(subject, out var userId)
                            ? await manager.FindByIdAsync(userId.ToString())
                            : null;
                        if (user is null || !user.IsActive || !string.Equals(user.SecurityStamp, tokenStamp, StringComparison.Ordinal))
                            context.Fail("Token has been revoked.");
                    }
                };
            });

        var authorization = services.AddAuthorizationBuilder();
        foreach (var permission in Permissions.All)
            authorization.AddPolicy(permission, policy => policy.RequireClaim(Permissions.ClaimType, permission));

        services.AddSingleton(TimeProvider.System);
        services.AddScoped<IEmailSender, EmailSender>();
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddScoped<DatabaseSeeder>();
        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);
        services.AddHostedService<RefreshTokenCleanupService>();
        return services;
    }
}
