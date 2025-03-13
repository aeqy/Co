using Co.Infrastructure.Data;

namespace Co.WebApi.extensions;

/// <summary>
/// OpenIddict配置类
/// </summary>
public static class OpenIddictConfiguration
{
    /// <summary>
    /// 配置OpenIddict
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection ConfigureOpenIddict(this IServiceCollection services, IConfiguration configuration)
    {
        // 配置JWT选项
        var jwtOptions = configuration.GetSection("JwtOptions");
        var accessTokenExpiration = jwtOptions.GetValue<int>("AccessTokenExpiration");
        var refreshTokenExpiration = jwtOptions.GetValue<int>("RefreshTokenExpiration");

        services.AddOpenIddict()
            // 注册OpenIddict核心组件
            .AddCore(options =>
            {
                // 配置OpenIddict使用Entity Framework Core存储授权、应用程序和令牌
                options.UseEntityFrameworkCore()
                    .UseDbContext<CoDbContext>();
            })
            
            // 注册OpenIddict服务器组件
            .AddServer(options =>
            {
                // 启用密码和刷新令牌流程
                options.AllowPasswordFlow()
                      .AllowRefreshTokenFlow();

                // 设置端点
                options.SetTokenEndpointUris("/api/auth/token");
                
                // 注册签名和加密凭据
                options.AddDevelopmentEncryptionCertificate()
                      .AddDevelopmentSigningCertificate();

                // 注册ASP.NET Core主机并配置授权节点
                options.UseAspNetCore()
                      .EnableTokenEndpointPassthrough()
                      .DisableTransportSecurityRequirement(); // 开发环境可关闭HTTPS要求
                
                // 配置令牌
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(accessTokenExpiration))
                      .SetRefreshTokenLifetime(TimeSpan.FromMinutes(refreshTokenExpiration))
                      .SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(60));
            })
            
            // 注册OpenIddict验证组件
            .AddValidation(options =>
            {
                // 导入OpenIddict服务器配置
                options.UseLocalServer();
                
                // 注册ASP.NET Core主机
                options.UseAspNetCore();
            });

        return services;
    }
}