using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Co.WebApi.Extensions;


public static class ServiceCollectionExtensions
{
    public static IServiceCollection ConfigureServicesDatabase(this IServiceCollection services,
        IConfiguration configuration)
    {
        // 配置数据库上下文，使用 PostgreSQL 数据库
        services.AddDbContext<CoDbContext>(options =>
        {
            // 从配置文件中获取数据库连接字符串，使用 Npgsql 来连接 PostgreSQL 数据库
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));

            // 配置 OpenIddict
            options.UseOpenIddict();
        });

        return services; // 返回服务集合
    }
    
    public static IServiceCollection AddJwtAuthorization(this IServiceCollection services)
    {
        services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:7179"; // 认证服务器地址
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false // 验证 audience
                };
            });

        return services; // 返回服务集合
    }
}