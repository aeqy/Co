using Co.Domain.Entities;
using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;

namespace Co.WebApi.Extensions;

public static class OpenIddictExtensions
{
    public static IServiceCollection AddOpenIddictServer(this IServiceCollection services)
    {
        services.AddIdentity<AppUser, IdentityRole<Guid>>()
            .AddEntityFrameworkStores<CoDbContext>()
            .AddDefaultTokenProviders();
        
        
        services.AddOpenIddict()
            .AddCore(options =>
            {
                // 配置 OpenIddict 使用 EF Core
                options.UseEntityFrameworkCore()
                    .UseDbContext<CoDbContext>();
            })
            .AddServer(options =>
            {
                options
                    .AllowAuthorizationCodeFlow() // 启用 Authorization Code 授权流程
                    .RequireProofKeyForCodeExchange() // 强制 PKCE
                    .AllowRefreshTokenFlow() // 启用 Refresh Token 授权流程
                    .AllowClientCredentialsFlow()   // 启用 Client Credentials 授权流程
                    .AllowPasswordFlow() // 启用 Password 授权流程
                    .SetTokenEndpointUris("/connect/token") // 令牌端点
                    .SetAuthorizationEndpointUris("/connect/authorize") // 授权端点
                    
                    
                    .SetUserInfoEndpointUris("/connect/userinfo")   // 用户信息端点
                    

                    // 配置签名和加密凭证
                    .AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();

                // 启用 JWT 令牌
                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough();
                
            })
            .AddValidation(options =>
            {
                options.UseLocalServer(); // 使用本地服务器作为验证提供程序
                options.UseAspNetCore();
            });

        return services; // 返回服务集合
    }
}