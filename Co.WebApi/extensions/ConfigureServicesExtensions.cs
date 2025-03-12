using Co.WebApi.extensions;

namespace Co.WebApi.Extensions;

public static class ConfigureServicesExtensions
{
    public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddControllers();
        services.AddLogging(logging => logging.AddConsole()); // 建议替换为 Serilog 或 NLog
        services.AddSwaggerDocumentation();
    }

    public static void Configure(this WebApplication app)
    {
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