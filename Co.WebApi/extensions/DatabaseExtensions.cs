using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Co.WebApi.extensions;

/// <summary>
/// 数据库扩展类
/// </summary>
public static class DatabaseExtensions
{
    /// <summary>
    /// 添加数据库服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddDatabaseServices(this IServiceCollection services, IConfiguration configuration)
    {
        // 获取连接字符串
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        // var connectionStringTemplate = configuration.GetConnectionString("DefaultConnection");
        // string password = Environment.GetEnvironmentVariable("DB_PASSWORD");
        // if (string.IsNullOrEmpty(password))
        // {
        //     throw new ArgumentNullException(nameof(password), "DB_PASSWORD 环境变量不能为空");
        // }
        // var connectionString = connectionStringTemplate.Replace("${DB_PASSWORD}", password);
        // Console.WriteLine($"DB_PASSWORD environment variable: {password}");
        // Console.WriteLine($"Final connection string: {connectionString}");
        
        // 注册数据库上下文
        services.AddDbContext<CoDbContext>(options =>
        {
            options.UseNpgsql(connectionString, npgsqlOptions =>
            {
                // 设置迁移程序集
                npgsqlOptions.MigrationsAssembly("Co.Infrastructure");
                
                // 设置重试策略
                npgsqlOptions.EnableRetryOnFailure(3);
            });
        });

        // 注册诊断
        services.AddDatabaseDeveloperPageExceptionFilter();

        return services;
    }
    
    /// <summary>
    /// 初始化数据库
    /// </summary>
    /// <param name="serviceProvider">服务提供者</param>
    /// <param name="logger">日志记录器</param>
    public static async Task InitializeDatabaseAsync(this IServiceProvider serviceProvider, ILogger logger)
    {
        try
        {
            using var scope = serviceProvider.CreateScope();
            var seedService = scope.ServiceProvider.GetRequiredService<SeedDataService>();
            await seedService.SeedAsync();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "初始化数据库时发生错误");
            throw; // 或者根据需要进行其他处理
        }
    }
}