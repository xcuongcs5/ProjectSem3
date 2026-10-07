# ProjectSem3 API

Bộ khung ASP.NET Core Web API dùng .NET 10, SQL Server, ASP.NET Core Identity, JWT access token, refresh-token rotation và phân quyền theo permission.

## Kiến trúc

```text
src/ProjectSem3.Api         API, controller, middleware, composition root
src/ProjectSem3.Application Hợp đồng, DTO và application abstractions
src/ProjectSem3.Domain      Entity, role và permission constants
src/ProjectSem3.Infrastructure EF Core, Identity, JWT và database seed
tests/ProjectSem3.UnitTests Unit tests
tests/ProjectSem3.IntegrationTests Integration tests dùng SQLite in-memory
```

API hiện có:

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/logout-all`
- `POST /api/v1/auth/confirm-email`
- `POST /api/v1/auth/resend-confirmation`
- `POST /api/v1/auth/forgot-password`
- `POST /api/v1/auth/reset-password`
- `POST /api/v1/auth/change-password`
- `GET/POST /api/v1/auth/mfa/*`
- `GET /api/v1/auth/me`
- `GET /api/v1/admin/users`
- `PATCH /api/v1/admin/users/{userId}/status`
- `PUT /api/v1/admin/users/{userId}/roles`
- `GET/PUT /api/v1/admin/roles/*`
- `GET /api/v1/admin/audit-logs`
- `GET /health/live`
- `GET /health/ready`

## Chạy local

Yêu cầu: .NET SDK 10 và SQL Server LocalDB hoặc một SQL Server khác.

Không lưu JWT key hay mật khẩu Admin vào `appsettings.json`. Thiết lập User Secrets:

```powershell
dotnet user-secrets set --project src/ProjectSem3.Api "Jwt:SigningKey" "replace-with-a-random-secret-of-at-least-32-bytes"
dotnet user-secrets set --project src/ProjectSem3.Api "SeedAdmin:Email" "admin@example.com"
dotnet user-secrets set --project src/ProjectSem3.Api "SeedAdmin:Password" "StrongAdminPass!123"
dotnet run --project src/ProjectSem3.Api -- --migrate
dotnet run --project src/ProjectSem3.Api
```

Migration/seed chạy bằng tiến trình riêng với cờ `--migrate`, không chạy trong startup của API. Ở Development, email xác nhận và đặt lại mật khẩu được ghi vào log; không dùng chế độ này ở production. Swagger UI nằm tại `/swagger`.

Nếu không dùng LocalDB, đặt connection string bằng User Secrets:

```powershell
dotnet user-secrets set --project src/ProjectSem3.Api "ConnectionStrings:DefaultConnection" "Server=localhost,1433;Database=ProjectSem3Db;User Id=sa;Password=YOUR_PASSWORD;TrustServerCertificate=True"
```

## Chạy bằng Docker

Sao chép `.env.example` thành `.env`, thay toàn bộ giá trị mẫu bằng secrets thực (bao gồm SMTP) rồi chạy:

```powershell
docker compose up --build
```

Compose chạy migration một lần trước khi khởi động API, đồng thời persist SQL data và Data Protection keys bằng Docker volumes. Cổng `8080` phục vụ HTTP nội bộ; production phải đặt reverse proxy TLS phía trước và không công khai trực tiếp cổng này. Swagger mặc định chỉ bật trong Development.

## Migration và test

```powershell
dotnet run --project src/ProjectSem3.Api -- --migrate
dotnet test ProjectSem3.slnx
dotnet build ProjectSem3.slnx
```

Migration ban đầu nằm trong `src/ProjectSem3.Infrastructure/Persistence/Migrations`.

## Ghi chú bảo mật

- Access token tồn tại 15 phút; refresh token tồn tại 14 ngày.
- Refresh token chỉ lưu bản SHA-256 trong database, được rotate sau mỗi lần refresh và có phát hiện reuse theo token family.
- Refresh token gửi bằng cookie `HttpOnly`, `Secure`, `SameSite=Strict`.
- Endpoint auth bị giới hạn 10 request/phút/IP.
- Sai mật khẩu 5 lần khóa tài khoản 15 phút.
- Email phải được xác nhận trước khi đăng nhập; SMTP bắt buộc trong cấu hình production.
- Có TOTP MFA và recovery codes; recovery codes chỉ được trả một lần khi bật MFA.
- Role mặc định: `Admin`, `Staff`, `User`; authorization endpoint quản trị dùng permission claims.
- JWT mang security stamp và bị từ chối ngay khi user bị khóa, đổi mật khẩu, MFA, role hoặc permission.
- `/health/live` chỉ kiểm tra tiến trình; `/health/ready` kiểm tra kết nối SQL Server.
- Data Protection keys được persist trong Docker volume. Với môi trường nhiều node, dùng shared volume/Redis/Azure Blob và bảo vệ key at rest bằng KMS/certificate.
- Chỉ proxy nằm trong `ReverseProxy:KnownProxies` được phép cung cấp forwarded headers; cấu hình IP proxy khi triển khai.
- Refresh token hết hạn hoặc bị thu hồi quá 30 ngày được background service dọn định kỳ.

Trước khi go-live cần thay toàn bộ placeholder secret, đặt `AllowedHosts` theo domain thực, cấu hình HTTPS/reverse proxy, backup database, monitoring/alerting và secret manager của môi trường triển khai.
