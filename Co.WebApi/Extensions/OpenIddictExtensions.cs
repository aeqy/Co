using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;

namespace Co.WebApi.Extensions;

/// <summary>
/// OpenIddict 配置的扩展方法。
/// </summary>
public static class OpenIddictExtensions
{
    /// <summary>
    /// 配置 OpenIddict 服务，包括 Identity 和 OpenIddict Server。
    /// </summary>
    /// <param name="services">服务集合。</param>
    /// <param name="configuration">应用程序配置。</param>
    public static IServiceCollection AddOpenIddictServer(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>()
            .AddEntityFrameworkStores<CoDbContext>()
            .AddDefaultTokenProviders();

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<CoDbContext>();
            })
            .AddServer(options =>
            {
                // 从配置中读取端点 URI
                options.SetTokenEndpointUris(configuration["OpenIddict:TokenEndpoint"] ?? "/connect/token")
                    .SetAuthorizationEndpointUris(configuration["OpenIddict:AuthorizationEndpoint"] ??
                                                  "/connect/authorize")
                    .SetUserInfoEndpointUris(configuration["OpenIddict:UserInfoEndpoint"] ?? "/connect/userinfo");

                options.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange()
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow()
                    .AllowPasswordFlow();

                // 根据环境选择证书
                if (configuration["ASPNETCORE_ENVIRONMENT"] == "Development")
                {
                    options.AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();
                }
                else
                {
                    // TODO: 在生产环境中，从证书存储加载正式证书
                    // options.AddEncryptionCertificate(证书)
                    // options.AddSigningCertificate(证书);
                    throw new InvalidOperationException("生产环境必须配置正式证书！");
                }

                options.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }
}