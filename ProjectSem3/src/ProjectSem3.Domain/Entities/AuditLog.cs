namespace ProjectSem3.Domain.Entities;

public sealed class AuditLog
{
    public long Id { get; set; }
    public Guid? UserId { get; set; }
    public required string Action { get; set; }
    public required string Resource { get; set; }
    public string? ResourceId { get; set; }
    public required string Result { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
