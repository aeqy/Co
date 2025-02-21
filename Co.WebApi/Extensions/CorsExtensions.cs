namespace Co.WebApi.Extensions;

public static class CorsExtensions
{
    public static void AddAppCors(this IServiceCollection services, IConfiguration configuration)
    {
        // 从配置中读取 CORS 设置 (可选，但推荐)
        var allowedOrigins = configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? new string[] { };
        var allowAllOrigins = configuration.GetValue<bool>("Cors:AllowAllOrigins");

        services.AddCors(options =>
        {
            options.AddPolicy("AppCorsPolicy", policy =>
            {
                if (allowAllOrigins)
                {
                    // 允许所有来源 (仅用于开发环境!)
                    policy.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                }
                else
                {
                    // 允许指定的来源
                    policy.WithOrigins(allowedOrigins)
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials(); // 如果需要 Cookie
                }
            });
        });
    }

    public static void UseAppCors(this IApplicationBuilder app)
    {
        app.UseCors("AppCorsPolicy");
    }
}