using System.Security.Claims;
using Co.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Co.Infrastructure.Services;

/// <summary>
/// 身份服务实现
/// </summary>
public class IdentityService : IIdentityService
{
    private readonly UserManager<IdentityUser<Guid>> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ILogger<IdentityService> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="userManager">用户管理器</param>
    /// <param name="roleManager">角色管理器</param>
    /// <param name="logger">日志记录器</param>
    public IdentityService(
        UserManager<IdentityUser<Guid>> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        ILogger<IdentityService> logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// 获取所有用户
    /// </summary>
    /// <returns>用户列表</returns>
    public async Task<List<IdentityUser<Guid>>> GetAllUsersAsync()
    {
        try
        {
            return await _userManager.Users.ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取所有用户时发生错误");
            throw;
        }
    }

    /// <summary>
    /// 通过ID获取用户
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>用户</returns>
    public async Task<IdentityUser<Guid>?> GetUserByIdAsync(string userId)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return null;

            return await _userManager.FindByIdAsync(userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "通过ID获取用户时发生错误: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// 通过用户名获取用户
    /// </summary>
    /// <param name="username">用户名</param>
    /// <returns>用户</returns>
    public async Task<IdentityUser<Guid>?> GetUserByUsernameAsync(string username)
    {
        try
        {
            if (string.IsNullOrEmpty(username))
                return null;

            return await _userManager.FindByNameAsync(username);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "通过用户名获取用户时发生错误: {Username}", username);
            throw;
        }
    }

    /// <summary>
    /// 通过电子邮件获取用户
    /// </summary>
    /// <param name="email">电子邮件</param>
    /// <returns>用户</returns>
    public async Task<IdentityUser<Guid>?> GetUserByEmailAsync(string email)
    {
        try
        {
            if (string.IsNullOrEmpty(email))
                return null;

            return await _userManager.FindByEmailAsync(email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "通过电子邮件获取用户时发生错误: {Email}", email);
            throw;
        }
    }

    /// <summary>
    /// 创建用户
    /// </summary>
    /// <param name="user">用户</param>
    /// <param name="password">密码</param>
    /// <param name="roles">角色列表</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> CreateUserAsync(IdentityUser<Guid> user, string password,
        List<string> roles)
    {
        try
        {
            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return (false, result.Errors.Select(e => e.Description).ToArray());
            }

            if (roles != null && roles.Any())
            {
                foreach (var role in roles)
                {
                    if (!await _roleManager.RoleExistsAsync(role))
                    {
                        await _roleManager.CreateAsync(new IdentityRole<Guid>(role));
                    }
                }

                result = await _userManager.AddToRolesAsync(user, roles);
                if (!result.Succeeded)
                {
                    return (false, result.Errors.Select(e => e.Description).ToArray());
                }
            }

            return (true, Array.Empty<string>());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建用户时发生错误: {Username}", user.UserName);
            throw;
        }
    }

    /// <summary>
    /// 更新用户
    /// </summary>
    /// <param name="user">用户</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> UpdateUserAsync(IdentityUser<Guid> user)
    {
        try
        {
            if (user == null)
                return (false, new[] { "用户不能为空" });

            var existingUser = await _userManager.FindByIdAsync(user.Id.ToString());
            if (existingUser == null)
                return (false, new[] { "用户不存在" });

            existingUser.UserName = user.UserName;
            existingUser.Email = user.Email;
            existingUser.PhoneNumber = user.PhoneNumber;
            existingUser.EmailConfirmed = user.EmailConfirmed;
            existingUser.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
            existingUser.TwoFactorEnabled = user.TwoFactorEnabled;
            existingUser.LockoutEnabled = user.LockoutEnabled;
            existingUser.LockoutEnd = user.LockoutEnd;

            var result = await _userManager.UpdateAsync(existingUser);
            return result.Succeeded
                ? (true, Array.Empty<string>())
                : (false, result.Errors.Select(e => e.Description).ToArray());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "更新用户时发生错误: {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// 更新用户角色
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="roles">角色列表</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> UpdateUserRolesAsync(string userId, List<string> roles)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return (false, new[] { "用户ID无效" });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return (false, new[] { "用户不存在" });

            var userRoles = await _userManager.GetRolesAsync(user);
            var removeResult = await _userManager.RemoveFromRolesAsync(user, userRoles);
            if (!removeResult.Succeeded)
            {
                return (false, removeResult.Errors.Select(e => e.Description).ToArray());
            }

            if (roles != null && roles.Any())
            {
                foreach (var role in roles)
                {
                    if (!await _roleManager.RoleExistsAsync(role))
                    {
                        await _roleManager.CreateAsync(new IdentityRole<Guid>(role));
                    }
                }

                var addResult = await _userManager.AddToRolesAsync(user, roles);
                if (!addResult.Succeeded)
                {
                    return (false, addResult.Errors.Select(e => e.Description).ToArray());
                }
            }

            return (true, Array.Empty<string>());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "更新用户角色时发生错误: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// 删除用户
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> DeleteUserAsync(string userId)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return (false, new[] { "用户ID无效" });

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return (false, new[] { "用户不存在" });

            var result = await _userManager.DeleteAsync(user);
            return result.Succeeded
                ? (true, Array.Empty<string>())
                : (false, result.Errors.Select(e => e.Description).ToArray());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除用户时发生错误: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// 获取所有角色
    /// </summary>
    /// <returns>角色列表</returns>
    public async Task<List<IdentityRole<Guid>>> GetAllRolesAsync()
    {
        try
        {
            return await _roleManager.Roles.ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取所有角色时发生错误");
            throw;
        }
    }

    /// <summary>
    /// 获取用户的所有角色
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>角色列表</returns>
    public async Task<List<string>> GetUserRolesAsync(string userId)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return new List<string>();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new List<string>();

            return (await _userManager.GetRolesAsync(user)).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取用户角色时发生错误: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// 创建角色
    /// </summary>
    /// <param name="role">角色</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> CreateRoleAsync(IdentityRole<Guid> role)
    {
        try
        {
            var result = await _roleManager.CreateAsync(role);
            return result.Succeeded
                ? (true, Array.Empty<string>())
                : (false, result.Errors.Select(e => e.Description).ToArray());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建角色时发生错误: {RoleName}", role.Name);
            throw;
        }
    }

    /// <summary>
    /// 删除角色
    /// </summary>
    /// <param name="roleId">角色ID</param>
    /// <returns>结果</returns>
    public async Task<(bool Succeeded, string[] Errors)> DeleteRoleAsync(string roleId)
    {
        try
        {
            if (string.IsNullOrEmpty(roleId) || !Guid.TryParse(roleId, out _))
                return (false, new[] { "角色ID无效" });

            var role = await _roleManager.FindByIdAsync(roleId);
            if (role == null)
                return (false, new[] { "角色不存在" });

            var result = await _roleManager.DeleteAsync(role);
            return result.Succeeded
                ? (true, Array.Empty<string>())
                : (false, result.Errors.Select(e => e.Description).ToArray());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除角色时发生错误: {RoleId}", roleId);
            throw;
        }
    }

    /// <summary>
    /// 更新用户的刷新令牌
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="refreshTokenExpiryTime">刷新令牌过期时间</param>
    /// <returns>结果</returns>
    public async Task<bool> UpdateUserRefreshTokenAsync(string userId, string refreshToken,
        DateTime refreshTokenExpiryTime)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return false;

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return false;

            var refreshTokenClaim = new Claim("RefreshToken", refreshToken);
            var refreshTokenExpiryTimeClaim = new Claim("RefreshTokenExpiryTime", refreshTokenExpiryTime.ToString("o"));

            var existingClaims = await _userManager.GetClaimsAsync(user);
            var existingRefreshTokenClaim = existingClaims.FirstOrDefault(c => c.Type == "RefreshToken");
            var existingRefreshTokenExpiryTimeClaim =
                existingClaims.FirstOrDefault(c => c.Type == "RefreshTokenExpiryTime");

            if (existingRefreshTokenClaim != null)
                await _userManager.RemoveClaimAsync(user, existingRefreshTokenClaim);

            if (existingRefreshTokenExpiryTimeClaim != null)
                await _userManager.RemoveClaimAsync(user, existingRefreshTokenExpiryTimeClaim);

            await _userManager.AddClaimAsync(user, refreshTokenClaim);
            await _userManager.AddClaimAsync(user, refreshTokenExpiryTimeClaim);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "更新用户刷新令牌时发生错误: {UserId}", userId);
            return false;
        }
    }

    /// <summary>
    /// 获取用户的声明列表
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>声明列表</returns>
    public async Task<List<Claim>> GetUserClaimsAsync(string userId)
    {
        try
        {
            if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out _))
                return new List<Claim>();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new List<Claim>();

            // 获取用户基本声明
            var claims = (await _userManager.GetClaimsAsync(user)).ToList();
            
            // 获取用户角色并添加到声明中
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                // 同时添加OpenIddict标准格式的角色声明
                claims.Add(new Claim("role", role));
                claims.Add(new Claim("roles", role));
                claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", role));
                
                // OpenIddict特定格式
                claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Role, role));
            }
            
            // 添加用户ID和用户名基本声明
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            claims.Add(new Claim(ClaimTypes.Name, user.UserName));
            
            
            // 增加兼容性 - 使用OpenIddict标准格式添加主要声明
            claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject, user.Id.ToString()));
            claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Name, user.UserName));
            
            if (!string.IsNullOrEmpty(user.Email))
            {
                claims.Add(new Claim(ClaimTypes.Email, user.Email));
                claims.Add(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Email, user.Email));
            }
            
            _logger.LogInformation("为用户 {UserId} 获取声明，包含 {ClaimCount} 个声明，角色: {Roles}", 
                userId, claims.Count, string.Join(", ", roles));
            
            return claims;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取用户声明时发生错误: {UserId}", userId);
            throw;
        }
    }
}