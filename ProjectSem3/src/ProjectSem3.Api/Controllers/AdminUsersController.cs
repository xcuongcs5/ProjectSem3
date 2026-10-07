using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSem3.Application.Abstractions;
using ProjectSem3.Application.Authentication;
using ProjectSem3.Domain.Constants;

namespace ProjectSem3.Api.Controllers;

[Authorize]
[Route("api/v1/admin/users")]
public sealed class AdminUsersController(IIdentityService identityService) : ApiControllerBase
{
    [HttpGet]
    [Authorize(Policy = Permissions.UsersView)]
    [ProducesResponseType<PagedResult<UserProfile>>(StatusCodes.Status200OK)]
    public async Task<ActionResult<PagedResult<UserProfile>>> GetUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null,
        CancellationToken cancellationToken = default) =>
        Ok(await identityService.GetUsersAsync(page, pageSize, search, cancellationToken));

    [HttpPatch("{userId:guid}/status")]
    [Authorize(Policy = Permissions.UsersLock)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetStatus(
        Guid userId,
        UpdateUserStatusRequest request,
        CancellationToken cancellationToken)
    {
        await identityService.SetUserStatusAsync(userId, request.IsActive, CurrentUserId, cancellationToken);
        return NoContent();
    }

    [HttpPut("{userId:guid}/roles")]
    [Authorize(Policy = Permissions.UsersAssignRole)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetRoles(
        Guid userId,
        SetUserRolesRequest request,
        CancellationToken cancellationToken)
    {
        await identityService.SetUserRolesAsync(userId, request.Roles, CurrentUserId, cancellationToken);
        return NoContent();
    }
}
