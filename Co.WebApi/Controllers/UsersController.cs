using System.Security.Claims;
using Co.Domain.Interfaces;
using Co.WebApi.Models.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace Co.WebApi.Controllers;


/// <summary>
/// 用户控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
public class UsersController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly ILogger<UsersController> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="identityService">身份服务</param>
    /// <param name="logger">日志记录器</param>
    public UsersController(IIdentityService identityService, ILogger<UsersController> logger)
    {
        _identityService = identityService;
        _logger = logger;
    }

    /// <summary>
    /// 获取当前用户的声明信息（调试用）
    /// </summary>
    [HttpGet("debug/claims")]
    public IActionResult GetUserClaims()
    {
        _logger.LogInformation("正在获取当前用户声明信息（调试）");

        var claims = User.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList();

        var identities = User.Identities.Select(i => new
        {
            AuthenticationType = i.AuthenticationType,
            Name = i.Name,
            IsAuthenticated = i.IsAuthenticated,
            NameClaimType = i.NameClaimType,
            RoleClaimType = i.RoleClaimType,
            Claims = i.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList()
        }).ToList();

        var userRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type == "role").Select(c => c.Value)
            .ToList();

        var isAdmin = User.IsInRole("Admin");
        var isSuperAdmin = User.IsInRole("SuperAdmin");

        _logger.LogInformation("用户声明数量: {ClaimCount}", claims.Count);
        _logger.LogInformation("用户角色: {Roles}", string.Join(", ", userRoles));
        _logger.LogInformation("IsInRole(Admin): {IsAdmin}, IsInRole(SuperAdmin): {IsSuperAdmin}", isAdmin,
            isSuperAdmin);

        return Ok(new
        {
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
            UserName = User.Identity?.Name,
            UserId = User.FindFirstValue(ClaimTypes.NameIdentifier),
            Claims = claims,
            Identities = identities,
            Roles = userRoles,
            IsAdmin = isAdmin,
            IsSuperAdmin = isSuperAdmin
        });
    }

    /// <summary>
    /// 获取所有用户（仅限管理员）
    /// </summary>
    /// <returns>用户列表</returns>
    [HttpGet]
    [Authorize(Roles = "SuperAdmin,Admin",
        AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<ActionResult<IEnumerable<IdentityUser<Guid>>>> GetUsers()
    {
        _logger.LogInformation("开始获取所有用户");

        // 调试信息
        var userRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type == "role").Select(c => c.Value).ToList();
        _logger.LogInformation("当前用户角色: {Roles}", string.Join(", ", userRoles));
        _logger.LogInformation("IsInRole(Admin): {IsAdmin}, IsInRole(SuperAdmin): {IsSuperAdmin}", 
            User.IsInRole("Admin"), User.IsInRole("SuperAdmin"));
            
        var allClaims = User.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList();
        _logger.LogInformation("所有声明: {Claims}", 
            string.Join("; ", allClaims.Select(c => $"{c.Type}={c.Value}")));
        
        var users = await _identityService.GetAllUsersAsync();

        // 隐藏敏感信息
        foreach (var user in users)
        {
            user.PasswordHash = null;
            user.SecurityStamp = null;
            user.ConcurrencyStamp = null;
            // user.RefreshToken = null;
        }

        _logger.LogInformation("成功获取所有用户，共 {Count} 个", users.Count);
        return Ok(users);
    }
    
    /// <summary>
    /// 获取当前用户信息
    /// </summary>
    /// <returns>用户信息</returns>
    [HttpGet("current")]
    public async Task<ActionResult<IdentityUser<Guid>>> GetCurrentUser()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        _logger.LogInformation("正在获取当前用户信息，用户ID: {UserId}", userId);

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("获取当前用户失败，未找到用户ID");
            return Unauthorized();
        }
        
        var user = await _identityService.GetUserByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("获取当前用户失败，用户不存在: {UserId}", userId);
            return NotFound();
        }
        
        // 隐藏敏感信息
        user.PasswordHash = null;
        user.SecurityStamp = null;
        user.ConcurrencyStamp = null;
        // user.RefreshToken = null;

        _logger.LogInformation("成功获取当前用户信息: {UserId}", userId);
        return Ok(user);
    }
    
    /// <summary>
    /// 获取用户信息（仅限管理员）
    /// </summary>
    /// <param name="id">用户ID</param>
    /// <returns>用户信息</returns>
    [HttpGet("{id}")]
    [Authorize(Roles = "SuperAdmin,Admin",
        AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<ActionResult<IdentityUser<Guid>>> GetUser(string id)
    {
        _logger.LogInformation("开始获取用户信息，用户ID: {UserId}", id);

        var user = await _identityService.GetUserByIdAsync(id);
        if (user == null)
        {
            _logger.LogWarning("获取用户失败，用户不存在: {UserId}", id);
            return NotFound();
        }

        // 隐藏敏感信息
        user.PasswordHash = null;
        user.SecurityStamp = null;
        user.ConcurrencyStamp = null;
        // user.RefreshToken = null;

        _logger.LogInformation("成功获取用户信息: {UserId}", id);
        return Ok(user);
    }
    
    /// <summary>
    /// 更新用户角色（仅限超级管理员）
    /// </summary>
    /// <param name="id">用户ID</param>
    /// <param name="roles">角色列表</param>
    /// <returns>更新结果</returns>
    [HttpPut("{id}/roles")]
    [Authorize(Roles = "SuperAdmin", AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> UpdateUserRoles(string id, [FromBody] List<string> roles)
    {
        _logger.LogInformation("开始更新用户角色，用户ID: {UserId}", id);
        var result = await _identityService.UpdateUserRolesAsync(id, roles);
        if (!result.Succeeded)
        {
            _logger.LogWarning("更新用户角色失败，用户ID: {UserId}, 错误: {Errors}", 
                id, string.Join(", ", result.Errors));
            return BadRequest(new { errors = result.Errors });
        }
        
        _logger.LogInformation("用户角色更新成功，用户ID: {UserId}", id);
        return Ok(new { message = "用户角色更新成功" });
    }
    
    /// <summary>
    /// 更新用户资料
    /// </summary>
    /// <param name="model">用户资料更新模型</param>
    /// <returns>更新结果</returns>
    [HttpPut("profile")]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }
        
        var user = await _identityService.GetUserByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }
        
        // 更新用户资料
        // user.FirstName = model.FirstName;
        // user.LastName = model.LastName;
        user.PhoneNumber = model.PhoneNumber;
        // user.UpdatedAt = DateTime.UtcNow;
        
        var result = await _identityService.UpdateUserAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors });
        }
        
        _logger.LogInformation("用户资料更新成功，用户ID: {UserId}", userId);
        return Ok(new { message = "用户资料更新成功" });
    }
    
    /// <summary>
    /// 删除用户（仅限超级管理员）
    /// </summary>
    /// <param name="id">用户ID</param>
    /// <returns>删除结果</returns>
    [HttpDelete("{id}")]
    [Authorize(Roles = "SuperAdmin", AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> DeleteUser(string id)
    {
        _logger.LogInformation("开始删除用户，用户ID: {UserId}", id);
        var result = await _identityService.DeleteUserAsync(id);
        if (!result.Succeeded)
        {
            _logger.LogWarning("删除用户失败，用户ID: {UserId}, 错误: {Errors}", 
                id, string.Join(", ", result.Errors));
            return BadRequest(new { errors = result.Errors });
        }
        
        _logger.LogInformation("用户删除成功，用户ID: {UserId}", id);
        return Ok(new { message = "用户删除成功" });
    }
}
