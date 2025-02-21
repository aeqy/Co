using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Co.Infrastructure.Data;

/// <summary>
/// 数据库上下文工厂，用于设计时工具（如 EF Core 迁移）。
/// </summary>
public class CoDbContextFactory : IDesignTimeDbContextFactory<CoDbContext>
{
    /// <summary>
    /// 创建 CoDbContext 实例。
    /// </summary>
    /// <param name="args">命令行参数（未使用）。</param>
    /// <returns>配置好的 CoDbContext 实例。</returns>
    public CoDbContext CreateDbContext(string[] args)
    {
        var envName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";
        var basePath = Path.Combine(Directory.GetCurrentDirectory(), "../Co.WebApi");
        
        var configuration = new ConfigurationBuilder()
            .SetBasePath(basePath)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddJsonFile($"appsettings.{envName}.json", optional: true)
            .Build();

        var connectionString = configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException("未配置连接字符串。请检查 appsettings.json 中的 'DefaultConnection' 设置。");
        }

        var optionsBuilder = new DbContextOptionsBuilder<CoDbContext>();
        optionsBuilder.UseNpgsql(connectionString); // 使用 PostgreSQL 数据库

        if (envName == "Development")
        {
            optionsBuilder.EnableSensitiveDataLogging(); // 仅在开发环境中启用敏感数据日志
        }

        optionsBuilder.UseLoggerFactory(LoggerFactory.Create(builder => builder.AddConsole()));

        // 工厂不需要 IWebHostEnvironment，传入模拟环境
        // var env = new HostingEnvironment { EnvironmentName = envName };
        // 创建 IHostEnvironment 的简单实现
        var env = new SimpleHostEnvironment { EnvironmentName = envName };
        return new CoDbContext(optionsBuilder.Options, env);
    }

    // 实现 IHostEnvironment 接口的简单类
    private class SimpleHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = default!;
        public string ApplicationName { get; set; } = default!;
        public string ContentRootPath { get; set; } = default!;
        public IFileProvider ContentRootFileProvider { get; set; } = default!;
    }
}