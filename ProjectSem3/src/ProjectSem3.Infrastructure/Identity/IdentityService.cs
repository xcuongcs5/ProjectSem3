using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ProjectSem3.Application.Abstractions;
using ProjectSem3.Application.Authentication;
using ProjectSem3.Application.Common.Exceptions;
using ProjectSem3.Domain.Constants;
using ProjectSem3.Domain.Entities;
using ProjectSem3.Infrastructure.Authentication;
using ProjectSem3.Infrastructure.Email;
using ProjectSem3.Infrastructure.Persistence;

namespace ProjectSem3.Infrastructure.Identity;

public sealed class IdentityService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    RoleManager<IdentityRole<Guid>> roleManager,
    ApplicationDbContext dbContext,
    IEmailSender emailSender,
    IOptions<JwtOptions> jwtOptions,
    IOptions<EmailOptions> emailOptions,
    ILogger<IdentityService> logger,
    TimeProvider timeProvider) : IIdentityService
{
    private readonly JwtOptions _jwt = jwtOptions.Value;
    private readonly EmailOptions _email = emailOptions.Value;

    public async Task<UserProfile> RegisterAsync(
        RegisterRequest request,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        var email = request.Email.Trim();
        var userName = request.UserName.Trim();

        if (await userManager.FindByEmailAsync(email) is not null)
            throw new ConflictException("Email hoặc tên đăng nhập đã được sử dụng.");

        if (await userManager.FindByNameAsync(userName) is not null)
            throw new ConflictException("Email hoặc tên đăng nhập đã được sử dụng.");

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = email,
            UserName = userName,
            CreatedAtUtc = now,
            IsActive = true
        };

        var result = await userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            throw new ValidationException(string.Join(" ", result.Errors.Select(x => x.Description)));

        result = await userManager.AddToRoleAsync(user, Roles.User);
        if (!result.Succeeded)
        {
            await userManager.DeleteAsync(user);
            throw new ValidationException("Không thể gán vai trò mặc định cho tài khoản.");
        }

        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.register", "user", user.Id.ToString(), "success", ipAddress, userAgent, now));
        await dbContext.SaveChangesAsync(cancellationToken);
        await TrySendConfirmationAsync(user, cancellationToken);
        return await MapProfileAsync(user);
    }

    public async Task ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(request.UserId.ToString())
            ?? throw new ValidationException("Token xác nhận không hợp lệ.");
        if (user.EmailConfirmed)
            return;

        var result = await userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
            throw new ValidationException("Token xác nhận không hợp lệ hoặc đã hết hạn.");

        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.confirm-email", "user", user.Id.ToString(), "success", null, null, timeProvider.GetUtcNow().UtcDateTime));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task ResendConfirmationAsync(string email, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByEmailAsync(email.Trim());
        if (user is { IsActive: true, EmailConfirmed: false })
            await TrySendConfirmationAsync(user, cancellationToken);
    }

    public async Task SendPasswordResetAsync(string email, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByEmailAsync(email.Trim());
        if (user is not { IsActive: true, EmailConfirmed: true })
            return;

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var link = $"{_email.FrontendBaseUrl.TrimEnd('/')}/reset-password?userId={user.Id}&token={Uri.EscapeDataString(token)}";
        await emailSender.SendAsync(
            user.Email!,
            "Đặt lại mật khẩu ProjectSem3",
            $"<p>Nhấn vào liên kết sau để đặt lại mật khẩu:</p><p><a href=\"{WebUtility.HtmlEncode(link)}\">Đặt lại mật khẩu</a></p>",
            cancellationToken);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(request.UserId.ToString())
            ?? throw new ValidationException("Token đặt lại mật khẩu không hợp lệ.");
        var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
        if (!result.Succeeded)
            throw new ValidationException(string.Join(" ", result.Errors.Select(x => x.Description)));

        await RevokeAllSessionsAsync(user.Id, null, cancellationToken);
        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.reset-password", "user", user.Id.ToString(), "success", null, null, timeProvider.GetUtcNow().UtcDateTime));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task ChangePasswordAsync(Guid userId, ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        var result = await userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
            throw new ValidationException(string.Join(" ", result.Errors.Select(x => x.Description)));

        await userManager.UpdateSecurityStampAsync(user);
        await RevokeAllSessionsAsync(user.Id, null, cancellationToken);
        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.change-password", "user", user.Id.ToString(), "success", null, null, timeProvider.GetUtcNow().UtcDateTime));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<MfaSetupResponse> GetMfaSetupAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(key))
        {
            EnsureSucceeded(await userManager.ResetAuthenticatorKeyAsync(user));
            key = await userManager.GetAuthenticatorKeyAsync(user);
        }

        var issuer = Uri.EscapeDataString(_jwt.Issuer);
        var account = Uri.EscapeDataString(user.Email ?? user.UserName ?? user.Id.ToString());
        return new MfaSetupResponse(key!, $"otpauth://totp/{issuer}:{account}?secret={key}&issuer={issuer}&digits=6");
    }

    public async Task<MfaRecoveryCodesResponse> EnableMfaAsync(Guid userId, string code, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        var normalizedCode = code.Replace(" ", string.Empty).Replace("-", string.Empty);
        if (!await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, normalizedCode))
            throw new ValidationException("Mã xác thực không hợp lệ.");

        EnsureSucceeded(await userManager.SetTwoFactorEnabledAsync(user, true));
        await userManager.UpdateSecurityStampAsync(user);
        var codes = (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))?.ToArray() ?? [];
        await RevokeAllSessionsAsync(user.Id, null, cancellationToken);
        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.enable-mfa", "user", user.Id.ToString(), "success", null, null, timeProvider.GetUtcNow().UtcDateTime));
        await dbContext.SaveChangesAsync(cancellationToken);
        return new MfaRecoveryCodesResponse(codes);
    }

    public async Task DisableMfaAsync(Guid userId, string password, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        if (!await userManager.CheckPasswordAsync(user, password))
            throw new UnauthorizedException();

        EnsureSucceeded(await userManager.SetTwoFactorEnabledAsync(user, false));
        EnsureSucceeded(await userManager.ResetAuthenticatorKeyAsync(user));
        await userManager.UpdateSecurityStampAsync(user);
        await RevokeAllSessionsAsync(user.Id, null, cancellationToken);
        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.disable-mfa", "user", user.Id.ToString(), "success", null, null, timeProvider.GetUtcNow().UtcDateTime));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<AuthSession> LoginAsync(
        LoginRequest request,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        var key = request.EmailOrUserName.Trim();
        var user = key.Contains('@')
            ? await userManager.FindByEmailAsync(key)
            : await userManager.FindByNameAsync(key);

        var now = timeProvider.GetUtcNow().UtcDateTime;
        if (user is null || !user.IsActive)
            throw new UnauthorizedException();

        var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.login", "user", user.Id.ToString(), "failed", ipAddress, userAgent, now));
            await dbContext.SaveChangesAsync(cancellationToken);
            throw new UnauthorizedException();
        }

        if (user.TwoFactorEnabled)
        {
            var validSecondFactor = false;
            if (!string.IsNullOrWhiteSpace(request.RecoveryCode))
                validSecondFactor = (await userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.RecoveryCode.Replace(" ", string.Empty))).Succeeded;
            else if (!string.IsNullOrWhiteSpace(request.TwoFactorCode))
                validSecondFactor = await userManager.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    request.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty));

            if (!validSecondFactor)
                throw new UnauthorizedException("Yêu cầu mã xác thực hai bước hợp lệ.");
        }

        user.LastLoginAtUtc = now;
        await userManager.UpdateAsync(user);

        var session = await CreateSessionAsync(user, NewRandomToken(), ipAddress, userAgent, now, cancellationToken);
        dbContext.AuditLogs.Add(CreateAudit(user.Id, "auth.login", "user", user.Id.ToString(), "success", ipAddress, userAgent, now));
        await dbContext.SaveChangesAsync(cancellationToken);
        return session;
    }

    public async Task<AuthSession> RefreshAsync(
        string refreshToken,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var tokenHash = HashToken(refreshToken);
        var currentToken = await dbContext.RefreshTokens.SingleOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken)
            ?? throw new UnauthorizedException("Refresh token không hợp lệ.");

        if (currentToken.RevokedAtUtc is not null)
        {
            await RevokeFamilyAsync(currentToken.UserId, currentToken.FamilyId, ipAddress, now, cancellationToken);
            throw new UnauthorizedException("Phát hiện refresh token đã được sử dụng lại; phiên đăng nhập đã bị thu hồi.");
        }

        if (currentToken.IsExpired(now))
            throw new UnauthorizedException("Refresh token đã hết hạn.");

        var user = await userManager.FindByIdAsync(currentToken.UserId.ToString());
        if (user is null || !user.IsActive)
            throw new UnauthorizedException();

        var rawToken = NewRandomToken();
        var nextToken = CreateRefreshToken(user.Id, rawToken, currentToken.FamilyId, ipAddress, userAgent, now);
        currentToken.RevokedAtUtc = now;
        currentToken.RevokedByIp = ipAddress;
        currentToken.ReplacedByTokenId = nextToken.Id;
        dbContext.RefreshTokens.Add(nextToken);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new UnauthorizedException("Refresh token đã được sử dụng.");
        }

        return await BuildSessionAsync(user, rawToken, nextToken.ExpiresAtUtc, now);
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken, string? ipAddress, CancellationToken cancellationToken)
    {
        var tokenHash = HashToken(refreshToken);
        var token = await dbContext.RefreshTokens.SingleOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken);
        if (token is null || token.RevokedAtUtc is not null)
            return;

        token.RevokedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        token.RevokedByIp = ipAddress;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeAllSessionsAsync(Guid userId, string? ipAddress, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await dbContext.RefreshTokens
            .Where(x => x.UserId == userId && x.RevokedAtUtc == null && x.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.RevokedAtUtc, now)
                .SetProperty(x => x.RevokedByIp, ipAddress), cancellationToken);
    }

    public async Task<UserProfile> GetProfileAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        return await MapProfileAsync(user);
    }

    public async Task<PagedResult<UserProfile>> GetUsersAsync(
        int page,
        int pageSize,
        string? search,
        CancellationToken cancellationToken)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var query = userManager.Users.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            query = query.Where(x =>
                (x.Email != null && x.Email.Contains(term)) ||
                (x.UserName != null && x.UserName.Contains(term)));
        }

        var total = await query.CountAsync(cancellationToken);
        var users = await query.OrderBy(x => x.UserName)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        var items = new List<UserProfile>(users.Count);
        foreach (var user in users)
            items.Add(await MapProfileAsync(user));

        return new PagedResult<UserProfile>(items, page, pageSize, total);
    }

    public async Task SetUserStatusAsync(Guid userId, bool isActive, Guid actorId, CancellationToken cancellationToken)
    {
        if (userId == actorId && !isActive)
            throw new ValidationException("Bạn không thể tự vô hiệu hóa tài khoản của mình.");

        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        user.IsActive = isActive;
        user.UpdatedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
        await userManager.UpdateSecurityStampAsync(user);
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
            throw new ValidationException(string.Join(" ", result.Errors.Select(x => x.Description)));

        if (!isActive)
            await RevokeAllSessionsAsync(userId, null, cancellationToken);

        dbContext.AuditLogs.Add(CreateAudit(actorId, "users.set-status", "user", userId.ToString(), "success", null, null, user.UpdatedAtUtc.Value));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task SetUserRolesAsync(
        Guid userId,
        IReadOnlyCollection<string> roles,
        Guid actorId,
        CancellationToken cancellationToken)
    {
        var canonicalRoles = Roles.All
            .Where(allowed => roles.Any(requested => string.Equals(allowed, requested, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        if (canonicalRoles.Length != roles.Distinct(StringComparer.OrdinalIgnoreCase).Count())
            throw new ValidationException("Danh sách vai trò chứa giá trị không hợp lệ.");

        if (userId == actorId && !canonicalRoles.Contains(Roles.Admin))
            throw new ValidationException("Bạn không thể tự gỡ vai trò Admin của mình.");

        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new NotFoundException("Không tìm thấy người dùng.");
        var currentRoles = await userManager.GetRolesAsync(user);

        if (currentRoles.Contains(Roles.Admin) && !canonicalRoles.Contains(Roles.Admin))
        {
            var admins = await userManager.GetUsersInRoleAsync(Roles.Admin);
            if (admins.Count <= 1)
                throw new ConflictException("Hệ thống phải còn ít nhất một Admin.");
        }

        var removeResult = await userManager.RemoveFromRolesAsync(user, currentRoles.Except(canonicalRoles));
        if (!removeResult.Succeeded)
            throw new ValidationException(string.Join(" ", removeResult.Errors.Select(x => x.Description)));

        var addResult = await userManager.AddToRolesAsync(user, canonicalRoles.Except(currentRoles));
        if (!addResult.Succeeded)
            throw new ValidationException(string.Join(" ", addResult.Errors.Select(x => x.Description)));

        await userManager.UpdateSecurityStampAsync(user);

        var now = timeProvider.GetUtcNow().UtcDateTime;
        dbContext.AuditLogs.Add(CreateAudit(actorId, "users.set-roles", "user", userId.ToString(), "success", null, null, now));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyCollection<RoleDetails>> GetRolesAsync(CancellationToken cancellationToken)
    {
        var roles = await roleManager.Roles.OrderBy(x => x.Name).ToListAsync(cancellationToken);
        var result = new List<RoleDetails>(roles.Count);
        foreach (var role in roles)
        {
            var permissions = (await roleManager.GetClaimsAsync(role))
                .Where(x => x.Type == Permissions.ClaimType)
                .Select(x => x.Value)
                .OrderBy(x => x)
                .ToArray();
            result.Add(new RoleDetails(role.Name!, permissions));
        }
        return result;
    }

    public async Task SetRolePermissionsAsync(
        string roleName,
        IReadOnlyCollection<string> permissions,
        Guid actorId,
        CancellationToken cancellationToken)
    {
        var normalized = permissions.Distinct(StringComparer.Ordinal).ToArray();
        if (normalized.Any(x => !Permissions.All.Contains(x, StringComparer.Ordinal)))
            throw new ValidationException("Danh sách permission chứa giá trị không hợp lệ.");

        var role = await roleManager.FindByNameAsync(roleName)
            ?? throw new NotFoundException("Không tìm thấy vai trò.");
        var current = (await roleManager.GetClaimsAsync(role)).Where(x => x.Type == Permissions.ClaimType).ToArray();
        foreach (var claim in current.Where(x => !normalized.Contains(x.Value, StringComparer.Ordinal)))
            EnsureSucceeded(await roleManager.RemoveClaimAsync(role, claim));
        foreach (var permission in normalized.Except(current.Select(x => x.Value), StringComparer.Ordinal))
            EnsureSucceeded(await roleManager.AddClaimAsync(role, new Claim(Permissions.ClaimType, permission)));

        var users = await userManager.GetUsersInRoleAsync(role.Name!);
        foreach (var user in users)
            await userManager.UpdateSecurityStampAsync(user);

        dbContext.AuditLogs.Add(CreateAudit(actorId, "roles.set-permissions", "role", role.Name, "success", null, null, timeProvider.GetUtcNow().UtcDateTime));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<PagedResult<AuditLogDto>> GetAuditLogsAsync(
        int page,
        int pageSize,
        string? action,
        CancellationToken cancellationToken)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var query = dbContext.AuditLogs.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(action))
            query = query.Where(x => x.Action == action.Trim());

        var total = await query.CountAsync(cancellationToken);
        var items = await query.OrderByDescending(x => x.CreatedAtUtc)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(x => new AuditLogDto(x.Id, x.UserId, x.Action, x.Resource, x.ResourceId, x.Result, x.IpAddress, x.UserAgent, x.CreatedAtUtc))
            .ToArrayAsync(cancellationToken);
        return new PagedResult<AuditLogDto>(items, page, pageSize, total);
    }

    private async Task<AuthSession> CreateSessionAsync(
        ApplicationUser user,
        string familyId,
        string? ipAddress,
        string? userAgent,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var rawToken = NewRandomToken();
        var refreshToken = CreateRefreshToken(user.Id, rawToken, familyId, ipAddress, userAgent, now);
        dbContext.RefreshTokens.Add(refreshToken);
        await dbContext.SaveChangesAsync(cancellationToken);
        return await BuildSessionAsync(user, rawToken, refreshToken.ExpiresAtUtc, now);
    }

    private async Task<AuthSession> BuildSessionAsync(ApplicationUser user, string refreshToken, DateTime refreshExpiresAt, DateTime now)
    {
        var roles = await userManager.GetRolesAsync(user);
        var permissions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var roleName in roles)
        {
            var role = await roleManager.FindByNameAsync(roleName);
            if (role is null) continue;
            var roleClaims = await roleManager.GetClaimsAsync(role);
            foreach (var claim in roleClaims.Where(x => x.Type == Permissions.ClaimType))
                permissions.Add(claim.Value);
        }

        var expiresAt = now.AddMinutes(_jwt.AccessTokenMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName ?? string.Empty),
            new("security_stamp", user.SecurityStamp ?? string.Empty)
        };
        claims.AddRange(roles.Select(x => new Claim(ClaimTypes.Role, x)));
        claims.AddRange(permissions.Select(x => new Claim(Permissions.ClaimType, x)));

        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SigningKey)),
            SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(_jwt.Issuer, _jwt.Audience, claims, now, expiresAt, credentials);
        var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);
        var profile = new AuthenticatedUser(user.Id, user.Email!, user.UserName!, roles.ToArray(), permissions.ToArray());
        return new AuthSession(encodedToken, expiresAt, refreshToken, refreshExpiresAt, profile);
    }

    private RefreshToken CreateRefreshToken(
        Guid userId,
        string rawToken,
        string familyId,
        string? ipAddress,
        string? userAgent,
        DateTime now) => new()
        {
            UserId = userId,
            TokenHash = HashToken(rawToken),
            FamilyId = familyId,
            CreatedAtUtc = now,
            ExpiresAtUtc = now.AddDays(_jwt.RefreshTokenDays),
            CreatedByIp = ipAddress,
            UserAgent = userAgent
        };

    private async Task RevokeFamilyAsync(
        Guid userId,
        string familyId,
        string? ipAddress,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await dbContext.RefreshTokens
            .Where(x => x.UserId == userId && x.FamilyId == familyId && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(x => x.RevokedAtUtc, now)
                .SetProperty(x => x.RevokedByIp, ipAddress), cancellationToken);
    }

    private async Task<UserProfile> MapProfileAsync(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        return new UserProfile(
            user.Id,
            user.Email ?? string.Empty,
            user.UserName ?? string.Empty,
            user.EmailConfirmed,
            user.IsActive,
            user.CreatedAtUtc,
            user.LastLoginAtUtc,
            roles.ToArray());
    }

    private async Task TrySendConfirmationAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        try
        {
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var link = $"{_email.FrontendBaseUrl.TrimEnd('/')}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
            await emailSender.SendAsync(
                user.Email!,
                "Xác nhận tài khoản ProjectSem3",
                $"<p>Nhấn vào liên kết sau để xác nhận tài khoản:</p><p><a href=\"{WebUtility.HtmlEncode(link)}\">Xác nhận email</a></p>",
                cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "Unable to send confirmation email for user {UserId}.", user.Id);
        }
    }

    private static void EnsureSucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
            throw new ValidationException(string.Join(" ", result.Errors.Select(x => x.Description)));
    }

    private static AuditLog CreateAudit(
        Guid? userId,
        string action,
        string resource,
        string? resourceId,
        string result,
        string? ipAddress,
        string? userAgent,
        DateTime now) => new()
        {
            UserId = userId,
            Action = action,
            Resource = resource,
            ResourceId = resourceId,
            Result = result,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAtUtc = now
        };

    private static string NewRandomToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    private static string HashToken(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
