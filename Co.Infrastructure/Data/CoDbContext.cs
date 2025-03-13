using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace Co.Infrastructure.Data;

public class CoDbContext(DbContextOptions<CoDbContext> options)
    : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid>(options)
{
    // 添加这个构造函数
    // OpenIddict 相关实体
    public DbSet<OpenIddictEntityFrameworkCoreApplication> OpenIddictApplications { get; set; } = null!;  // 客户端应用注册表
    public DbSet<OpenIddictEntityFrameworkCoreAuthorization> OpenIddictAuthorizations { get; set; } = null!; // 授权记录表
    public DbSet<OpenIddictEntityFrameworkCoreScope> OpenIddictScopes { get; set; } = null!; // 权限范围定义表
    public DbSet<OpenIddictEntityFrameworkCoreToken> OpenIddictTokens { get; set; } = null!; // 令牌存储表
    
    /// <summary>
    /// 配置模型，包括 Identity 和 OpenIddict 的表结构
    /// </summary>
    protected override void OnModelCreating(ModelBuilder model)
    {
        base.OnModelCreating(model);
        ConfigureIdentityTables(model);
        ConfigureOpenIddictTables(model);
    }

    private void ConfigureIdentityTables(ModelBuilder modelBuilder)
    {
        // 自定义Identity表名前缀
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            var tableName = entityType.GetTableName();
            if (tableName != null && tableName.StartsWith("AspNet"))
            {
                entityType.SetTableName(tableName.Replace("AspNet", "Co"));
            }
        }
            
        // modelBuilder.Entity<IdentityUserRole<Guid>>().ToTable("UserRoles");
        // modelBuilder.Entity<IdentityUserClaim<Guid>>().ToTable("UserClaims");
        // modelBuilder.Entity<IdentityUserLogin<Guid>>().ToTable("UserLogins");
        // modelBuilder.Entity<IdentityRoleClaim<Guid>>().ToTable("RoleClaims");
        // modelBuilder.Entity<IdentityUserToken<Guid>>().ToTable("UserTokens");
    }

    private void ConfigureOpenIddictTables(ModelBuilder modelBuilder)
    {
        modelBuilder.UseOpenIddict();
    }
}