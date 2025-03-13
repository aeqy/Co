using Co.Infrastructure.Data;
using Co.WebApi.extensions;
using DotNetEnv;
using Microsoft.EntityFrameworkCore;

namespace Co.WebApi.Extensions;

public static class ConfigureServicesExtensions
{
    public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDatabaseServices(configuration);
        services.AddOpenIddictServer(configuration);
        services.AddScoped<SeedDataService>();
        services.AddControllers();
        services.AddLogging(logging => logging.AddConsole()); // 建议替换为 Serilog 或 NLog
        services.AddSwaggerDocumentation();
        
    }

    public static void Configure(this WebApplication app)
    {
        // 初始化数据库
        var logger = app.Services.GetRequiredService<ILogger<Program>>();
        app.Services.InitializeDatabaseAsync(logger).GetAwaiter().GetResult();

        try
        {
            using var scope = app.Services.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<CoDbContext>();
            context.Database.Migrate();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "数据库迁移失败");
            throw; // 或者根据需要进行其他处理
        }
        app.UseSwaggerDocumentation();
        app.UseDefaultFiles(); // Use Default Files
        app.UseStaticFiles(); // Use Static Files
        app.UseAuthentication(); // Use Authentication
        app.UseAuthorization(); // Use Authorization
        app.MapControllers(); // Map Controllers
        app.UseRouting(); // Use Routing
        app.UseHttpsRedirection(); // Use Https Redirection
    }

}