using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Co.WebApi.Extensions;

public static class DatabaseExtensions
{
    /// <summary>
    /// 扩展方法，用于应用启动时为数据库应用迁移并种子数据。
    /// 该方法可以在应用程序启动时调用，确保数据库已应用迁移并填充种子数据。
    /// </summary>
    /// <param name="app">IApplicationBuilder，用于构建应用程序的服务</param>
    public static async Task SeedDatabaseAsync(this IApplicationBuilder app)
    {
        // 创建一个服务作用域，以便在作用域内获取所需的服务实例
        using (var scope = app.ApplicationServices.CreateScope())
        {
            // 获取服务提供者，用于解析需要的服务
            var services = scope.ServiceProvider;

            // 从依赖注入容器中获取数据库上下文 AppDbContext
            var dbContext = services.GetRequiredService<CoDbContext>();

            // 从依赖注入容器中获取种子数据服务 ISeedDataService
            var seedDataService = services.GetRequiredService<SeedDataService>();

            // 获取日志记录器，用于记录错误和信息日志
            var logger = services.GetRequiredService<ILogger<Program>>();

            try
            {
                // 应用数据库迁移，确保数据库结构与模型一致
                dbContext.Database.Migrate();

                // 调用种子数据服务以插入或更新数据库中的种子数据
                await seedDataService.SeedAsync();
            }
            catch (Exception ex)
            {
                // 捕获任何异常并记录错误日志
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }
    }
}