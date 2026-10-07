namespace ProjectSem3.Application.Abstractions;

public interface IEmailSender
{
    Task SendAsync(string recipient, string subject, string htmlBody, CancellationToken cancellationToken);
}
