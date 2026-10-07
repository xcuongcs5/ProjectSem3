namespace ProjectSem3.Domain.Constants;

public static class Roles
{
    public const string Admin = "Admin";
    public const string Staff = "Staff";
    public const string User = "User";

    public static readonly string[] All = [Admin, Staff, User];
}
