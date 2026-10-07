using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using ProjectSem3.Application.Authentication;
using ProjectSem3.Infrastructure.Identity;
using Xunit;

namespace ProjectSem3.IntegrationTests;

public sealed class AuthenticationFlowTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory = factory;
    private readonly HttpClient _client = factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        HandleCookies = true,
        AllowAutoRedirect = false
    });

    [Fact]
    public async Task RegisterLoginRefreshAndReadProfile_Succeeds()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var email = $"user-{suffix}@example.com";
        const string password = "StrongPass!123";

        var register = await _client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, $"user{suffix[..12]}", password));
        Assert.True(register.StatusCode == HttpStatusCode.Created, await register.Content.ReadAsStringAsync());

        var login = await _client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.True(login.StatusCode == HttpStatusCode.OK, await login.Content.ReadAsStringAsync());
        var loginJson = await login.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = loginJson.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var profile = await _client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);

        var forbidden = await _client.GetAsync("/api/v1/admin/users");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        _client.DefaultRequestHeaders.Authorization = null;
        var refresh = await _client.PostAsync("/api/v1/auth/refresh", null);
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Fact]
    public async Task LoginWithWrongPassword_ReturnsUnauthorized()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("missing@example.com", "WrongPass!123"));
        Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ChangedSecurityStamp_RevokesExistingAccessToken()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var email = $"revoke-{suffix}@example.com";
        const string password = "StrongPass!123";
        await _client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, $"revoke{suffix[..10]}", password));
        var login = await _client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = body.GetProperty("accessToken").GetString();

        using (var scope = _factory.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await manager.FindByEmailAsync(email);
            Assert.NotNull(user);
            Assert.True((await manager.UpdateSecurityStampAsync(user)).Succeeded);
        }

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await _client.GetAsync("/api/v1/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task HealthEndpoints_ReportLiveAndReady()
    {
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health/ready")).StatusCode);
    }
}
