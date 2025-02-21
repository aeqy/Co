using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Co.WebApi.Extensions;

/// <summary>
/// 服务集合的扩展方法，用于配置数据库和身份验证。
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// 配置数据库服务。
    /// </summary>
    public static IServiceCollection ConfigureServicesDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<CoDbContext>(options =>
        {
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
            options.UseOpenIddict();
        });
        return services;
    }

    /// <summary>
    /// 配置 JWT 身份验证。
    /// </summary>
    public static IServiceCollection AddJwtAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = configuration["Authentication:Authority"]; // 从配置中读取 Authority
                if (string.IsNullOrEmpty(options.Authority))
                {
                    throw new InvalidOperationException("未配置 Authentication:Authority。请检查 appsettings.json。");
                }
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false
                };
            });
        return services;
    }
}