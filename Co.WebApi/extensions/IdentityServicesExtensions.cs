using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Co.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;

namespace Co.WebApi.extensions;

/// <summary>
/// Identity服务扩展类
/// </summary>
public static class IdentityServicesExtensions
{
    /// <summary>
    /// 添加Identity服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
    {
        // 配置Identity选项
        var identityOptions = configuration.GetSection("IdentityOptions");
        
        // 添加Identity
        services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
            {
                // 密码设置
                options.Password.RequireDigit = identityOptions.GetValue<bool>("Password:RequireDigit");
                options.Password.RequireLowercase = identityOptions.GetValue<bool>("Password:RequireLowercase");
                options.Password.RequireUppercase = identityOptions.GetValue<bool>("Password:RequireUppercase");
                options.Password.RequireNonAlphanumeric = identityOptions.GetValue<bool>("Password:RequireNonAlphanumeric");
                options.Password.RequiredLength = identityOptions.GetValue<int>("Password:RequiredLength");
                
                // 用户设置
                options.User.RequireUniqueEmail = identityOptions.GetValue<bool>("User:RequireUniqueEmail");
                
                // 锁定设置
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.Parse(identityOptions.GetValue<string>("Lockout:DefaultLockoutTimeSpan"));
                options.Lockout.MaxFailedAccessAttempts = identityOptions.GetValue<int>("Lockout:MaxFailedAccessAttempts");
                options.Lockout.AllowedForNewUsers = identityOptions.GetValue<bool>("Lockout:AllowedForNewUsers");
            })
            .AddEntityFrameworkStores<CoDbContext>()
            .AddDefaultTokenProviders();
            
        // 配置OpenIddict
        services.ConfigureOpenIddict(configuration);
        
        // 添加Identity服务
        services.AddScoped<IIdentityService, IdentityService>();

        return services;
    }
}
