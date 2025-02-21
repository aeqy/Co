using Co.Infrastructure.Data;

namespace Co.WebApi.Extensions;

public static class ConfigureServicesExtensions
{
    public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.ConfigureServicesDatabase(configuration);
        services.AddOpenIddictServer(configuration);
        services.AddJwtAuthorization(configuration);
        services.AddScoped<SeedDataService>();
        services.AddControllers();
        services.AddSwaggerDocumentation();
        services.AddLogging(logging => logging.AddConsole()); // 建议替换为 Serilog 或 NLog
    }

    public static void Configure(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseSwaggerDocumentation();
        }
        else
        {
            app.UseExceptionHandler(errorApp =>
            {
                errorApp.Run(async context =>
                {
                    context.Response.StatusCode = 500;
                    await context.Response.WriteAsync("服务器内部错误，请稍后重试。");
                    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
                    logger.LogError("未处理的异常发生在请求 {Path}", context.Request.Path);
                });
            }); // 全局异常处理
        }

        app.UseAppCors(); // 使用扩展方法
        app.UseDefaultFiles(); // Use Default Files
        app.UseStaticFiles(); // Use Static Files
        app.UseAuthentication(); // Use Authentication
        app.UseAuthorization(); // Use Authorization
        app.MapControllers(); // Map Controllers
        app.UseRouting(); // Use Routing
        app.UseHttpsRedirection(); // Use Https Redirection
    }
}