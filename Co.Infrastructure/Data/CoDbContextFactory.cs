using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Co.Infrastructure.Data;

public class CoDbContextFactory : IDesignTimeDbContextFactory<CoDbContext>
{
    public CoDbContext CreateDbContext(string[] args)
    {
        try
        {
            // Define the base path for configuration
            var basePath = Path.Combine(Directory.GetCurrentDirectory(), "../Co.WebApi");

            // Build the configuration without SetBasePath
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .AddJsonFile(Path.Combine(basePath, "appsettings.json"), optional: false, reloadOnChange: true)
                .AddJsonFile(
                    Path.Combine(basePath,
                        $"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json"),
                    optional: true)
                .Build();

            var connectionString = configuration.GetConnectionString("DefaultConnection");

            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException(
                    "未配置连接字符串。请检查 appsettings.json 中的 ConnectionStrings:DefaultConnection 设置。");
            }

            var optionsBuilder = new DbContextOptionsBuilder<CoDbContext>();

            optionsBuilder.UseNpgsql(connectionString)
                .EnableSensitiveDataLogging() // Enable sensitive data logging for development only
                .UseLoggerFactory(LoggerFactory.Create(builder =>
                {
                    builder.AddConsole(); // Logs output to the console
                }));

            return new CoDbContext(optionsBuilder.Options);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"无法创建 DbContext：{ex.Message}", ex);
        }
    }
}