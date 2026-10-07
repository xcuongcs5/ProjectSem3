using ProjectSem3.Domain.Entities;
using Xunit;

namespace ProjectSem3.UnitTests;

public sealed class RefreshTokenTests
{
    [Fact]
    public void IsActive_WhenNotRevokedAndNotExpired_ReturnsTrue()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var token = CreateToken(now.AddMinutes(1));

        Assert.True(token.IsActive(now));
    }

    [Fact]
    public void IsActive_WhenRevoked_ReturnsFalse()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var token = CreateToken(now.AddMinutes(1));
        token.RevokedAtUtc = now;

        Assert.False(token.IsActive(now));
    }

    [Fact]
    public void IsExpired_AtExactExpiry_ReturnsTrue()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var token = CreateToken(now);

        Assert.True(token.IsExpired(now));
    }

    private static RefreshToken CreateToken(DateTime expiresAtUtc) => new()
    {
        UserId = Guid.NewGuid(),
        TokenHash = "HASH",
        FamilyId = "FAMILY",
        CreatedAtUtc = expiresAtUtc.AddDays(-1),
        ExpiresAtUtc = expiresAtUtc
    };
}
