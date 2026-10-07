using ProjectSem3.Application.Authentication;

namespace ProjectSem3.Application.Abstractions;

public interface IIdentityService
{
    Task<UserProfile> RegisterAsync(RegisterRequest request, string? ipAddress, string? userAgent, CancellationToken cancellationToken);
    Task ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken);
    Task ResendConfirmationAsync(string email, CancellationToken cancellationToken);
    Task SendPasswordResetAsync(string email, CancellationToken cancellationToken);
    Task ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken);
    Task ChangePasswordAsync(Guid userId, ChangePasswordRequest request, CancellationToken cancellationToken);
    Task<MfaSetupResponse> GetMfaSetupAsync(Guid userId, CancellationToken cancellationToken);
    Task<MfaRecoveryCodesResponse> EnableMfaAsync(Guid userId, string code, CancellationToken cancellationToken);
    Task DisableMfaAsync(Guid userId, string password, CancellationToken cancellationToken);
    Task<AuthSession> LoginAsync(LoginRequest request, string? ipAddress, string? userAgent, CancellationToken cancellationToken);
    Task<AuthSession> RefreshAsync(string refreshToken, string? ipAddress, string? userAgent, CancellationToken cancellationToken);
    Task RevokeRefreshTokenAsync(string refreshToken, string? ipAddress, CancellationToken cancellationToken);
    Task RevokeAllSessionsAsync(Guid userId, string? ipAddress, CancellationToken cancellationToken);
    Task<UserProfile> GetProfileAsync(Guid userId, CancellationToken cancellationToken);
    Task<PagedResult<UserProfile>> GetUsersAsync(int page, int pageSize, string? search, CancellationToken cancellationToken);
    Task SetUserStatusAsync(Guid userId, bool isActive, Guid actorId, CancellationToken cancellationToken);
    Task SetUserRolesAsync(Guid userId, IReadOnlyCollection<string> roles, Guid actorId, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<RoleDetails>> GetRolesAsync(CancellationToken cancellationToken);
    Task SetRolePermissionsAsync(string roleName, IReadOnlyCollection<string> permissions, Guid actorId, CancellationToken cancellationToken);
    Task<PagedResult<AuditLogDto>> GetAuditLogsAsync(int page, int pageSize, string? action, CancellationToken cancellationToken);
}
