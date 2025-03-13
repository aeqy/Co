using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Co.Domain.Interfaces;

/// <summary>
/// 身份服务接口
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// 获取所有用户
    /// </summary>
    /// <returns>用户列表</returns>
    Task<List<IdentityUser>> GetAllUsersAsync();

    /// <summary>
    /// 通过ID获取用户
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>用户</returns>
    Task<IdentityUser?> GetUserByIdAsync(string userId);

    /// <summary>
    /// 通过用户名获取用户
    /// </summary>
    /// <param name="username">用户名</param>
    /// <returns>用户</returns>
    Task<IdentityUser?> GetUserByUsernameAsync(string username);

    /// <summary>
    /// 通过电子邮件获取用户
    /// </summary>
    /// <param name="email">电子邮件</param>
    /// <returns>用户</returns>
    Task<IdentityUser?> GetUserByEmailAsync(string email);

    /// <summary>
    /// 创建用户
    /// </summary>
    /// <param name="user">用户</param>
    /// <param name="password">密码</param>
    /// <param name="roles">角色列表</param>
    /// <returns>结果</returns>
    Task<(bool Succeeded, string[] Errors)> CreateUserAsync(IdentityUser user, string password, List<string> roles);

    /// <summary>
    /// 更新用户
    /// </summary>
    /// <param name="user">用户</param>
    /// <returns>结果</returns>
    Task<(bool Succeeded, string[] Errors)> UpdateUserAsync(IdentityUser user);

    /// <summary>
    /// 更新用户角色
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="roles">角色列表</param>
    /// <returns>结果</returns>
    Task<(bool Succeeded, string[] Errors)> UpdateUserRolesAsync(string userId, List<string> roles);

    /// <summary>
    /// 删除用户
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>结果</returns>
    Task<(bool Succeeded, string[] Errors)> DeleteUserAsync(string userId);

    /// <summary>
    /// 获取所有角色
    /// </summary>
    /// <returns>角色列表</returns>
    Task<List<IdentityRole>> GetAllRolesAsync();

    /// <summary>
    /// 获取用户的所有角色
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>角色列表</returns>
    Task<List<string>> GetUserRolesAsync(string userId);

    /// <summary>
    /// 创建角色
    /// </summary>
    /// <param name="role">角色</param>
    /// <returns>结果</returns>
    Task<(bool Succeeded, string[] Errors)> CreateRoleAsync(IdentityRole role);

    /// <summary>
    /// 删除角色
    /// </summary>
    /// <param name="roleId">角色ID</param>
    /// <returns>结果</returns>
    Task<(bool Succeeded, string[] Errors)> DeleteRoleAsync(string roleId);

    /// <summary>
    /// 更新用户的刷新令牌
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="refreshTokenExpiryTime">刷新令牌过期时间</param>
    /// <returns>结果</returns>
    Task<bool> UpdateUserRefreshTokenAsync(string userId, string refreshToken, DateTime refreshTokenExpiryTime);

    /// <summary>
    /// 获取用户的声明列表
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>声明列表</returns>
    Task<List<Claim>> GetUserClaimsAsync(string userId);
}