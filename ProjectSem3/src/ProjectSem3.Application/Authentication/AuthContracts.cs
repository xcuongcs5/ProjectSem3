using System.ComponentModel.DataAnnotations;

namespace ProjectSem3.Application.Authentication;

public sealed record RegisterRequest(
    [Required, EmailAddress, MaxLength(256)] string Email,
    [Required, MinLength(3), MaxLength(50)] string UserName,
    [Required, MinLength(10), MaxLength(128)] string Password);

public sealed record LoginRequest(
    [Required, MaxLength(256)] string EmailOrUserName,
    [Required, MaxLength(128)] string Password,
    [MaxLength(20)] string? TwoFactorCode = null,
    [MaxLength(50)] string? RecoveryCode = null);

public sealed record ConfirmEmailRequest(
    Guid UserId,
    [Required] string Token);

public sealed record ResendConfirmationRequest(
    [Required, EmailAddress, MaxLength(256)] string Email);

public sealed record ForgotPasswordRequest(
    [Required, EmailAddress, MaxLength(256)] string Email);

public sealed record ResetPasswordRequest(
    Guid UserId,
    [Required] string Token,
    [Required, MinLength(10), MaxLength(128)] string NewPassword);

public sealed record ChangePasswordRequest(
    [Required, MaxLength(128)] string CurrentPassword,
    [Required, MinLength(10), MaxLength(128)] string NewPassword);

public sealed record VerifyMfaRequest([Required, MaxLength(20)] string Code);

public sealed record DisableMfaRequest([Required, MaxLength(128)] string Password);

public sealed record MfaSetupResponse(string SharedKey, string AuthenticatorUri);

public sealed record MfaRecoveryCodesResponse(IReadOnlyCollection<string> RecoveryCodes);

public sealed record AuthenticatedUser(
    Guid Id,
    string Email,
    string UserName,
    IReadOnlyCollection<string> Roles,
    IReadOnlyCollection<string> Permissions);

public sealed record AuthSession(
    string AccessToken,
    DateTime AccessTokenExpiresAtUtc,
    string RefreshToken,
    DateTime RefreshTokenExpiresAtUtc,
    AuthenticatedUser User);

public sealed record UserProfile(
    Guid Id,
    string Email,
    string UserName,
    bool EmailConfirmed,
    bool IsActive,
    DateTime CreatedAtUtc,
    DateTime? LastLoginAtUtc,
    IReadOnlyCollection<string> Roles);

public sealed record PagedResult<T>(IReadOnlyCollection<T> Items, int Page, int PageSize, int TotalCount);

public sealed record UpdateUserStatusRequest(bool IsActive);

public sealed record SetUserRolesRequest(
    [Required, MinLength(1)] IReadOnlyCollection<string> Roles);

public sealed record RoleDetails(string Name, IReadOnlyCollection<string> Permissions);

public sealed record SetRolePermissionsRequest(
    [Required] IReadOnlyCollection<string> Permissions);

public sealed record AuditLogDto(
    long Id,
    Guid? UserId,
    string Action,
    string Resource,
    string? ResourceId,
    string Result,
    string? IpAddress,
    string? UserAgent,
    DateTime CreatedAtUtc);
