using Co.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Co.Infrastructure.Data;

public class SeedDataService(
    CoDbContext context,
    UserManager<AppUser> userManager,
    RoleManager<IdentityRole<Guid>> roleManager,
    IOpenIddictApplicationManager applicationManager,
    ILogger<SeedDataService> logger)
{
    public async Task SeedAsync()
    {
        await context.Database.MigrateAsync();

        // 添加角色
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole<Guid>("Admin"));
        }

        if (!await roleManager.RoleExistsAsync("User"))
        {
            await roleManager.CreateAsync(new IdentityRole<Guid>("User"));
        }

        // 添加用户（不需要Email）
        var defaultUser = new AppUser
        {
            UserName = "admin",
            // Email = "example@example.com", // 忽略Email
            // 其他字段
        };

        var defaultPassword = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_PASSWORD") ?? "Admin@123";

        if (await userManager.FindByNameAsync(defaultUser.UserName) == null)
        {
            var result = await userManager.CreateAsync(defaultUser, defaultPassword);
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(defaultUser, "User");
                logger.LogInformation("Default user created with role 'User'.");
            }
            else
            {
                logger.LogError("Failed to create default user: {Errors}", string.Join(", ", result.Errors));
            }
        }

        // 配置 OpenIddict 应用程序种子数据
        var existingApp = await applicationManager.FindByClientIdAsync("my-client");

        if (existingApp == null)
        {
            // 创建新的客户端应用程序
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "my-client",
                ClientSecret = "your-client-secret", // 仅 confidential 客户端需要
                DisplayName = "My Client Application",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                }
            });
        }
        else
        {
            // 检查 existingApp 不为 null 后再调用 GetIdAsync
            var applicationId = await applicationManager.GetIdAsync(existingApp);

            if (applicationId != null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = "my-client",
                    ClientType = OpenIddictConstants.ClientTypes.Confidential,
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.Password,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken
                    }
                };

                // await applicationManager.UpdateAsync(applicationId, descriptor);

                // 确保这里是正确的 OpenIddict 应用程序对象，而不是 string
                var application = await applicationManager.FindByClientIdAsync(applicationId);
                if (application != null)
                {
                    await applicationManager.UpdateAsync(application, descriptor);
                }
            }
            else
            {
                logger.LogError("Failed to retrieve application ID for client 'my-client'.");
            }
        }
    }
}