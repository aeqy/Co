using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using OpenIddict.EntityFrameworkCore.Models;

namespace Co.Infrastructure.Data;

/// <summary>
/// 应用程序的数据库上下文，继承自 IdentityDbContext 以支持用户身份验证，并集成 OpenIddict。
/// </summary>
public class CoDbContext : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid>
{
    private readonly bool _isDevelopment;

    /// <summary>
    /// 构造函数，注入 DbContextOptions 和 IWebHostEnvironment。
    /// </summary>
    /// <param name="options">数据库上下文选项。</param>
    /// <param name="env">Web 主机环境，用于判断当前运行环境。</param>
    public CoDbContext(DbContextOptions<CoDbContext> options, IHostEnvironment env) : base(options)
    {
        _isDevelopment = env.IsDevelopment();
    }

    // OpenIddict 相关实体
    public DbSet<OpenIddictEntityFrameworkCoreApplication> OpenIddictApplications { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreAuthorization> OpenIddictAuthorizations { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreScope> OpenIddictScopes { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreToken> OpenIddictTokens { get; set; }

    /// <summary>
    /// 配置模型，包括 Identity 和 OpenIddict 的表结构。
    /// </summary>
    protected override void OnModelCreating(ModelBuilder model)
    {
        base.OnModelCreating(model);
        model.UseOpenIddict();
    }

    /// <summary>
    /// 配置数据库上下文选项，例如日志记录。
    /// </summary>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (_isDevelopment)
        {
            optionsBuilder.EnableSensitiveDataLogging(); // 仅在开发环境中启用敏感数据日志
        }
    }
}