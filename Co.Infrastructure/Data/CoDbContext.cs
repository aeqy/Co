using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Co.Infrastructure.Data;

/// <summary>
/// 配置数据库
/// </summary>
/// <param name="options"></param>
public class CoDbContext(DbContextOptions<CoDbContext> options) : DbContext(options)
{
    // 定义 OpenIddict 所需的实体
    public DbSet<OpenIddictEntityFrameworkCoreApplication> OpenIddictApplications { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreAuthorization> OpenIddictAuthorizations { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreScope> OpenIddictScopes { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreToken> OpenIddictTokens { get; set; }
    
    // 配置 OpenIddict
    protected override void OnModelCreating(ModelBuilder model)
    {
        base.OnModelCreating(model);
        
        model.UseOpenIddict();
    }
    
    // 启用敏感数据日志
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.EnableSensitiveDataLogging(false);
    }
}