namespace ProjectSem3.Infrastructure.Email;

public sealed class EmailOptions
{
    public const string SectionName = "Email";

    public string Mode { get; set; } = "Log";
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public bool EnableSsl { get; set; } = true;
    public string UserName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FromEmail { get; set; } = string.Empty;
    public string FromName { get; set; } = "ProjectSem3";
    public string FrontendBaseUrl { get; set; } = "http://localhost:3000";
}
