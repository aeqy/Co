using Co.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Validation.AspNetCore;

namespace Co.WebApi.extensions;

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
        // 添加 ASP.NET Core Identity 服务
        services.AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options =>
            {
                // 设置密码策略
                options.Password.RequireDigit = false; // 密码必须包含至少一个数字 (0-9)
                options.Password.RequireLowercase = false; // 密码必须包含至少一个小写字母 (a-z)
                options.Password.RequireUppercase = false; // 密码必须包含至少一个大写字母 (A-Z)
                options.Password.RequireNonAlphanumeric = false; // 密码可以不包含非字母数字字符 (例如：!@#$%^&*)
                options.Password.RequiredLength = 4; // 密码的最小长度为 4 个字符

                // 锁定设置
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;

                // 用户设置
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<CoDbContext>()
            .AddDefaultTokenProviders();

        // 添加 OpenIddict 服务
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<CoDbContext>();
            })
            .AddServer(options =>
            {
                // 启用令牌端点
                options.SetTokenEndpointUris("/connect/token");

                // 启用授权类型
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();
                options.AllowClientCredentialsFlow();

                // 注册签名和加密凭据
                options.AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();

                // 注册作用域
                options.RegisterScopes("api", "offline_access");

                // 在开发环境中禁用客户端身份验证要求
                options.AcceptAnonymousClients();

                // 在开发环境中使用引用令牌
                // options.UseReferenceTokens();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
        });
        return services;
    }
}