using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc;
using ProjectSem3.Application.Common.Exceptions;

namespace ProjectSem3.Api.Controllers;

[ApiController]
[Produces("application/json")]
public abstract class ApiControllerBase : ControllerBase
{
    protected Guid CurrentUserId
    {
        get
        {
            var value = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            return Guid.TryParse(value, out var id)
                ? id
                : throw new UnauthorizedException();
        }
    }

    protected string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();
    protected string? UserAgent => Request.Headers.UserAgent.ToString() is { Length: > 0 } value ? value[..Math.Min(value.Length, 512)] : null;
}
