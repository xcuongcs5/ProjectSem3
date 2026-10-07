namespace ProjectSem3.Application.Common.Exceptions;

public abstract class AppException(string message) : Exception(message)
{
    public abstract int StatusCode { get; }
    public abstract string ErrorCode { get; }
}

public sealed class ValidationException(string message) : AppException(message)
{
    public override int StatusCode => 400;
    public override string ErrorCode => "validation_error";
}

public sealed class UnauthorizedException(string message = "Thông tin xác thực không hợp lệ.") : AppException(message)
{
    public override int StatusCode => 401;
    public override string ErrorCode => "unauthorized";
}

public sealed class ForbiddenException(string message = "Bạn không có quyền thực hiện thao tác này.") : AppException(message)
{
    public override int StatusCode => 403;
    public override string ErrorCode => "forbidden";
}

public sealed class NotFoundException(string message) : AppException(message)
{
    public override int StatusCode => 404;
    public override string ErrorCode => "not_found";
}

public sealed class ConflictException(string message) : AppException(message)
{
    public override int StatusCode => 409;
    public override string ErrorCode => "conflict";
}
