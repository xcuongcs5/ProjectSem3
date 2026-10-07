using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ProjectSem3.Application.Common.Exceptions;

namespace ProjectSem3.Api.Middleware;

public sealed class GlobalExceptionHandler(
    IProblemDetailsService problemDetailsService,
    ILogger<GlobalExceptionHandler> logger,
    IHostEnvironment environment) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var (status, code, title) = exception switch
        {
            AppException appException => (appException.StatusCode, appException.ErrorCode, appException.Message),
            _ => (StatusCodes.Status500InternalServerError, "internal_error", "Đã xảy ra lỗi trong hệ thống.")
        };

        if (status >= 500)
            logger.LogError(exception, "Unhandled exception. TraceId: {TraceId}", httpContext.TraceIdentifier);
        else
            logger.LogWarning("Request failed with {ErrorCode}. TraceId: {TraceId}", code, httpContext.TraceIdentifier);

        var problem = new ProblemDetails
        {
            Status = status,
            Title = title,
            Type = $"https://projectsem3/errors/{code}",
            Instance = httpContext.Request.Path
        };
        problem.Extensions["code"] = code;
        problem.Extensions["traceId"] = httpContext.TraceIdentifier;
        if (environment.IsDevelopment() && exception is not AppException)
            problem.Extensions["detail"] = exception.Message;

        httpContext.Response.StatusCode = status;
        return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problem,
            Exception = exception
        });
    }
}
