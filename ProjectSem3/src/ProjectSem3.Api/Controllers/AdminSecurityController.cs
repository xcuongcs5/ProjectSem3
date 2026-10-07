using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectSem3.Application.Abstractions;
using ProjectSem3.Application.Authentication;
using ProjectSem3.Domain.Constants;

namespace ProjectSem3.Api.Controllers;

[Authorize]
[Route("api/v1/admin")]
public sealed class AdminSecurityController(IIdentityService identityService) : ApiControllerBase
{
    [HttpGet("roles")]
    [Authorize(Policy = Permissions.RolesView)]
    public async Task<ActionResult<IReadOnlyCollection<RoleDetails>>> GetRoles(CancellationToken cancellationToken) =>
        Ok(await identityService.GetRolesAsync(cancellationToken));

    [HttpPut("roles/{roleName}/permissions")]
    [Authorize(Policy = Permissions.RolesManage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetPermissions(
        string roleName,
        SetRolePermissionsRequest request,
        CancellationToken cancellationToken)
    {
        await identityService.SetRolePermissionsAsync(roleName, request.Permissions, CurrentUserId, cancellationToken);
        return NoContent();
    }

    [HttpGet("audit-logs")]
    [Authorize(Policy = Permissions.AuditLogsView)]
    public async Task<ActionResult<PagedResult<AuditLogDto>>> GetAuditLogs(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] string? action = null,
        CancellationToken cancellationToken = default) =>
        Ok(await identityService.GetAuditLogsAsync(page, pageSize, action, cancellationToken));
}
