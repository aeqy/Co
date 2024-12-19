using Microsoft.AspNetCore.Identity;

namespace Co.Domain.Entities;

/// <summary>
///  用户实体, 继承自 IdentityUser, 使用 Guid 做主键
/// </summary>
public class AppUser: IdentityUser<Guid>
{
    
}