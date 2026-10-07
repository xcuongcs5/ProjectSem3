using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ProjectSem3.Application.Abstractions;
using ProjectSem3.Application.Authentication;
using ProjectSem3.Application.Common.Exceptions;

namespace ProjectSem3.Api.Controllers;

[Route("api/v1/auth")]
public sealed class AuthController(IIdentityService identityService) : ApiControllerBase
{
    private const string RefreshCookieName = "__Host-projectsem3-refresh";

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("register")]
    [ProducesResponseType<UserProfile>(StatusCodes.Status201Created)]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken cancellationToken)
    {
        var user = await identityService.RegisterAsync(request, ClientIp, UserAgent, cancellationToken);
        return CreatedAtAction(nameof(Me), user);
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken cancellationToken)
    {
        var session = await identityService.LoginAsync(request, ClientIp, UserAgent, cancellationToken);
        SetRefreshCookie(session.RefreshToken, session.RefreshTokenExpiresAtUtc);
        return Ok(ToResponse(session));
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("refresh")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Refresh(CancellationToken cancellationToken)
    {
        if (!Request.Cookies.TryGetValue(RefreshCookieName, out var refreshToken) || string.IsNullOrWhiteSpace(refreshToken))
            throw new UnauthorizedException("Thiếu refresh token.");

        var session = await identityService.RefreshAsync(refreshToken, ClientIp, UserAgent, cancellationToken);
        SetRefreshCookie(session.RefreshToken, session.RefreshTokenExpiresAtUtc);
        return Ok(ToResponse(session));
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("confirm-email")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailRequest request, CancellationToken cancellationToken)
    {
        await identityService.ConfirmEmailAsync(request, cancellationToken);
        return NoContent();
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("resend-confirmation")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ResendConfirmation(ResendConfirmationRequest request, CancellationToken cancellationToken)
    {
        await identityService.ResendConfirmationAsync(request.Email, cancellationToken);
        return Accepted();
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("forgot-password")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        await identityService.SendPasswordResetAsync(request.Email, cancellationToken);
        return Accepted();
    }

    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        await identityService.ResetPasswordAsync(request, cancellationToken);
        return NoContent();
    }

    [AllowAnonymous]
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        if (Request.Cookies.TryGetValue(RefreshCookieName, out var refreshToken) && !string.IsNullOrWhiteSpace(refreshToken))
            await identityService.RevokeRefreshTokenAsync(refreshToken, ClientIp, cancellationToken);

        DeleteRefreshCookie();
        return NoContent();
    }

    [Authorize]
    [HttpPost("logout-all")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> LogoutAll(CancellationToken cancellationToken)
    {
        await identityService.RevokeAllSessionsAsync(CurrentUserId, ClientIp, cancellationToken);
        DeleteRefreshCookie();
        return NoContent();
    }

    [Authorize]
    [HttpPost("change-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        await identityService.ChangePasswordAsync(CurrentUserId, request, cancellationToken);
        DeleteRefreshCookie();
        return NoContent();
    }

    [Authorize]
    [HttpGet("mfa/setup")]
    public async Task<ActionResult<MfaSetupResponse>> GetMfaSetup(CancellationToken cancellationToken) =>
        Ok(await identityService.GetMfaSetupAsync(CurrentUserId, cancellationToken));

    [Authorize]
    [HttpPost("mfa/enable")]
    public async Task<ActionResult<MfaRecoveryCodesResponse>> EnableMfa(VerifyMfaRequest request, CancellationToken cancellationToken)
    {
        var response = await identityService.EnableMfaAsync(CurrentUserId, request.Code, cancellationToken);
        DeleteRefreshCookie();
        return Ok(response);
    }

    [Authorize]
    [HttpPost("mfa/disable")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DisableMfa(DisableMfaRequest request, CancellationToken cancellationToken)
    {
        await identityService.DisableMfaAsync(CurrentUserId, request.Password, cancellationToken);
        DeleteRefreshCookie();
        return NoContent();
    }

    [Authorize]
    [HttpGet("me", Name = nameof(Me))]
    [ProducesResponseType<UserProfile>(StatusCodes.Status200OK)]
    public async Task<ActionResult<UserProfile>> Me(CancellationToken cancellationToken) =>
        Ok(await identityService.GetProfileAsync(CurrentUserId, cancellationToken));

    private void SetRefreshCookie(string token, DateTime expiresAtUtc) =>
        Response.Cookies.Append(RefreshCookieName, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            Expires = expiresAtUtc,
            IsEssential = true
        });

    private void DeleteRefreshCookie() => Response.Cookies.Delete(RefreshCookieName, new CookieOptions
    {
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/"
    });

    private static object ToResponse(AuthSession session) => new
    {
        session.AccessToken,
        session.AccessTokenExpiresAtUtc,
        session.User
    };
}
