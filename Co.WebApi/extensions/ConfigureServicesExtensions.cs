using Co.Infrastructure.Data;
using Co.WebApi.extensions;
using Microsoft.EntityFrameworkCore;

namespace Co.WebApi.Extensions;

public static class ConfigureServicesExtensions
{
    public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
    {
        // 添加控制器和API功能
        services.AddControllers()
            .AddNewtonsoftJson();

        // 添加数据库服务
        services.AddDatabaseServices(configuration);

        // 添加Identity和认证服务
        services.AddIdentityServices(configuration);
        
        // 添加Redis缓存服务
        services.AddRedisCacheServices(configuration);

        // 添加种子数据服务
        services.AddScoped<SeedDataService>();

        // 添加日志服务
        services.AddLogging(logging => logging.AddConsole()); // 建议替换为 Serilog 或 NLog

        // 添加Swagger文档
        services.AddSwaggerDocumentation();
        // 添加CORS服务
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", builder =>
            {
                builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });
    }

    public static void Configure(this WebApplication app)
    {
        // 开发环境配置
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

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

        // 配置CORS
        app.UseCors("AllowAll");

        // 配置Swagger
        app.UseSwaggerDocumentation();

        // 配置静态文件和路由
        app.UseDefaultFiles(); // Use Default Files
        app.UseStaticFiles(); // Use Static Files
        app.UseRouting(); // Use Routing

        // 配置认证和授权
        app.UseAuthentication(); // Use Authentication
        app.UseAuthorization(); // Use Authorization

        // 映射端点
        app.MapControllers(); // Map Controllers

        // 配置HTTPS
        app.UseHttpsRedirection(); // Use Https Redirection
    }
}