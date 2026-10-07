namespace ProjectSem3.Domain.Constants;

public static class Permissions
{
    public const string ClaimType = "permission";

    public const string UsersView = "users.view";
    public const string UsersUpdate = "users.update";
    public const string UsersLock = "users.lock";
    public const string UsersAssignRole = "users.assign-role";
    public const string RolesView = "roles.view";
    public const string RolesManage = "roles.manage";
    public const string AuditLogsView = "audit-logs.view";

    public static readonly string[] All =
    [
        UsersView,
        UsersUpdate,
        UsersLock,
        UsersAssignRole,
        RolesView,
        RolesManage,
        AuditLogsView
    ];
}
