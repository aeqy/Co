using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Co.Infrastructure.Data;

/// <summary>
/// 数据种子服务，用于初始化数据库中的角色、用户和 OpenIddict 客户端。
/// </summary>
public class SeedDataService(
    CoDbContext context,
    UserManager<IdentityUser<Guid>> userManager,
    RoleManager<IdentityRole<Guid>> roleManager,
    IOpenIddictApplicationManager applicationManager,
    ILogger<SeedDataService> logger)
{
    private static class SeedConstants
    {
        public const string AdminRole = "Admin";
        public const string UserRole = "User";
        public const string DefaultAdminUsername = "admin";
        public const string ClientId = "my-client";
        public const string ClientSecret = "your-client-secret";
        public const string ClientDisplayName = "My Client Application";
    }

    /// <summary>
    /// 执行所有种子数据操作。
    /// </summary>
    public async Task SeedAsync()
    {
        try
        {
            await context.Database.MigrateAsync(); // 应用所有未完成的迁移
            await SeedRolesAsync();
            await SeedUsersAsync();
            await SeedOpenIddictApplicationsAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "种子数据初始化失败。");
            throw;
        }
    }

    private async Task SeedRolesAsync()
    {
        string[] roles = { SeedConstants.AdminRole, SeedConstants.UserRole };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
                if (!result.Succeeded)
                {
                    logger.LogError("创建角色 '{Role}' 失败: {Errors}", role,
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
                else
                {
                    logger.LogInformation("角色 '{Role}' 已创建。", role);
                }
            }
        }
    }

    private async Task SeedUsersAsync()
    {
        var defaultUser = new IdentityUser<Guid> { UserName = SeedConstants.DefaultAdminUsername };
        var defaultPassword = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_PASSWORD") ?? "Admin@123";

        if (await userManager.FindByNameAsync(defaultUser.UserName) == null)
        {
            var result = await userManager.CreateAsync(defaultUser, defaultPassword);
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(defaultUser, SeedConstants.AdminRole);
                logger.LogInformation("默认管理员用户 '{Username}' 已创建。", defaultUser.UserName);
            }
            else
            {
                logger.LogError("创建默认管理员用户失败: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
    }

    private async Task SeedOpenIddictApplicationsAsync()
    {
        var clientId = SeedConstants.ClientId;
        var existingApp = await applicationManager.FindByClientIdAsync(clientId);

        if (existingApp == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = SeedConstants.ClientSecret,
                DisplayName = SeedConstants.ClientDisplayName,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    OpenIddictConstants.Permissions.Scopes.Profile
                }
            });
            logger.LogInformation("OpenIddict 客户端 '{ClientId}' 已创建。", clientId);
        }
        else
        {
            logger.LogInformation("OpenIddict 客户端 '{ClientId}' 已存在，无需创建。", clientId);
            // TODO: 如果需要，可以在这里添加配置检查和更新逻辑
        }
    }

    //将数据库迁移和种子数据操作提取到一个单独的方法中
    public static async Task InitializeDatabaseAsync(IServiceProvider serviceProvider)
    {
        using (var scope = serviceProvider.CreateScope())
        {
            var seedService = scope.ServiceProvider.GetRequiredService<SeedDataService>();
            await seedService.SeedAsync();
        }
    }
}