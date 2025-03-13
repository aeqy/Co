using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Co.Infrastructure.Data;

public class SeedDataService(
    CoDbContext context,
    UserManager<IdentityUser<Guid>> userManager,
    RoleManager<IdentityRole<Guid>> roleManager,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictScopeManager scopeManager, // 添加 scopeManager
    IConfiguration configuration,
    ILogger<SeedDataService> logger)
{
    public async Task SeedAsync()
    {
        try
        {
            await context.Database.MigrateAsync();

            if (configuration.GetValue<bool>("SeedData:SeedRoles"))
            {
                await SeedRolesAsync();
            }

            if (configuration.GetValue<bool>("SeedData:SeedUsers"))
            {
                await SeedUsersAsync();
            }

            if (configuration.GetValue<bool>("SeedData:SeedOpenIddict"))
            {
                await SeedOpenIddictScopesAsync();
                await SeedOpenIddictApplicationsAsync();
            }

            logger.LogInformation("所有种子数据操作已完成");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "种子数据初始化失败");
            throw;
        }
    }

    private async Task SeedRolesAsync()
    {
        string[] roles = { "SuperAdmin", "Admin", "User", "Manager" };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                logger.LogInformation("创建角色: {Role}", role);

                var identityRole = new IdentityRole<Guid>(role);
                var result = await roleManager.CreateAsync(identityRole);

                if (!result.Succeeded)
                {
                    logger.LogError("创建角色 '{Role}' 失败: {Errors}", role,
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
    }

    private async Task SeedUsersAsync()
    {
        await CreateUserIfNotExistsAsync(
            "superadmin",
            "superadmin@example.com",
            configuration["SeedData:SuperAdminPassword"] ?? "SuperAdmin@123",
            new[] { "SuperAdmin" }
        );
        
        await CreateUserIfNotExistsAsync(
            "admin",
            "admin@example.com",
            configuration["SeedData:AdminPassword"] ?? "Admin@123",
            new[] { "Admin" }
        );

        await CreateUserIfNotExistsAsync(
            "user",
            "user@example.com",
            configuration["SeedData:UserPassword"] ?? "User@123",
            new[] { "User" }
        );

        await CreateUserIfNotExistsAsync(
            "manager",
            "manager@example.com",
            configuration["SeedData:ManagerPassword"] ?? "Manager@123",
            new[] { "Manager" }
        );
        
        // 创建一个测试用户，拥有所有角色
        await CreateUserIfNotExistsAsync(
            "test",
            "test@example.com",
            configuration["SeedData:TestUserPassword"] ?? "Test@123",
            new[] { "SuperAdmin", "Admin", "User", "Manager" }
        );
    }

    private async Task CreateUserIfNotExistsAsync(
        string userName,
        string email,
        string password,
        string[] roles)
    {
        var user = await userManager.FindByNameAsync(userName);

        if (user == null)
        {
            logger.LogInformation("创建用户: {UserName}", userName);

            user = new IdentityUser<Guid>
            {
                UserName = userName,
                Email = email,
                EmailConfirmed = true
            };

            // 添加日志记录，打印密码策略和实际使用的密码
            logger.LogInformation($"尝试创建用户 '{userName}'，密码：{password}");
            logger.LogInformation(
                $"密码策略：RequireDigit={userManager.Options.Password.RequireDigit}, RequireLowercase={userManager.Options.Password.RequireLowercase}, RequireUppercase={userManager.Options.Password.RequireUppercase}, RequireNonAlphanumeric={userManager.Options.Password.RequireNonAlphanumeric}, RequiredLength={userManager.Options.Password.RequiredLength}");
            logger.LogInformation($"实际使用的密码：{password}");
            var result = await userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                logger.LogInformation("为用户 '{UserName}' 添加角色: {Roles}", userName, string.Join(", ", roles));

                foreach (var role in roles)
                {
                    result = await userManager.AddToRoleAsync(user, role);

                    if (!result.Succeeded)
                    {
                        logger.LogError("将角色 '{Role}' 添加到用户 '{UserName}' 失败: {Errors}",
                            role, userName, string.Join(", ", result.Errors.Select(e => e.Description)));
                    }
                }
            }
            else
            {
                logger.LogError("创建用户 '{UserName}' 失败: {Errors}",
                    userName, string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            logger.LogInformation("用户 '{UserName}' 已存在，跳过创建", userName);
        }
    }

    private async Task SeedOpenIddictScopesAsync()
    {
        await CreateScopeIfNotExistsAsync("api", "API 访问权限", new[]
        {
            OpenIddictConstants.Permissions.Scopes.Profile,
            OpenIddictConstants.Permissions.Scopes.Email,
            OpenIddictConstants.Permissions.Scopes.Roles
        });

        await CreateScopeIfNotExistsAsync("offline_access", "离线访问权限");
    }

    private async Task CreateScopeIfNotExistsAsync(string name, string displayName, string[]? resources = null)
    {
        if (await scopeManager.FindByNameAsync(name) == null)
        {
            logger.LogInformation("创建作用域: {ScopeName}", name);

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = displayName,
                // Resources = { "api" }
            };

            if (resources != null)
            {
                foreach (var resource in resources)
                {
                    descriptor.Resources.Add(resource);
                }
            }

            await scopeManager.CreateAsync(descriptor);
        }
    }

    private async Task SeedOpenIddictApplicationsAsync()
    {
        await CreateApplicationIfNotExistsAsync(
            "spa-client",
            "SPA Client Application",
            // configuration["SeedData:OpenIddict:SpaClientSecret"] ?? "spa-client-secret",
            null,
            OpenIddictConstants.ClientTypes.Public,
            new[]
            {
                OpenIddictConstants.GrantTypes.AuthorizationCode,
                OpenIddictConstants.GrantTypes.RefreshToken
            },
            new[] { "https://localhost:5001/callback", "https://localhost:5001/silent-refresh.html" },
            new[] { "api", "offline_access" }
        );

        await CreateApplicationIfNotExistsAsync(
            "service-client",
            "Service Client Application",
            configuration["SeedData:OpenIddict:ServiceClientSecret"] ?? "service-client-secret",
            OpenIddictConstants.ClientTypes.Confidential,
            new[]
            {
                OpenIddictConstants.GrantTypes.ClientCredentials
            },
            Array.Empty<string>(),
            new[] { "api" }
        );

        await CreateApplicationIfNotExistsAsync(
            "password-client",
            "Password Client Application",
            configuration["SeedData:OpenIddict:PasswordClientSecret"] ?? "password-client-secret",
            OpenIddictConstants.ClientTypes.Confidential,
            new[]
            {
                OpenIddictConstants.GrantTypes.Password,
                OpenIddictConstants.GrantTypes.RefreshToken
            },
            Array.Empty<string>(),
            new[] { "api", "offline_access" }
        );
    }

    private async Task CreateApplicationIfNotExistsAsync(
        string clientId,
        string displayName,
        string clientSecret,
        string clientType,
        string[] grantTypes,
        string[] redirectUris,
        string[] scopes)
    {
        if (await applicationManager.FindByClientIdAsync(clientId) == null)
        {
            logger.LogInformation("创建 OpenIddict 客户端: {ClientId}", clientId);

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                DisplayName = displayName,
                ClientType = clientType
            };

            foreach (var grantType in grantTypes)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.GrantType + grantType);
            }

            foreach (var uri in redirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }

            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            if (grantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            }

            if (redirectUris.Any())
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);
            }

            foreach (var scope in scopes)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
            }

            await applicationManager.CreateAsync(descriptor);
        }
        else
        {
            logger.LogInformation("OpenIddict 客户端 '{ClientId}' 已存在，跳过创建", clientId);
        }
    }
}