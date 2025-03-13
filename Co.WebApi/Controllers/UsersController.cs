using Co.Domain.Interfaces;
using Co.WebApi.Models.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Co.WebApi.Controllers;


/// <summary>
/// 用户控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
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
    /// 获取所有用户（仅限管理员）
    /// </summary>
    /// <returns>用户列表</returns>
    [HttpGet]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public async Task<ActionResult<IEnumerable<IdentityUser>>> GetUsers()
    {
        var users = await _identityService.GetAllUsersAsync();
        
        // 隐藏敏感信息
        foreach (var user in users)
        {
            user.PasswordHash = null;
            user.SecurityStamp = null;
            user.ConcurrencyStamp = null;
            // user.RefreshToken = null;
        }
        
        return Ok(users);
    }
    
    /// <summary>
    /// 获取当前用户信息
    /// </summary>
    /// <returns>用户信息</returns>
    [HttpGet("current")]
    public async Task<ActionResult<IdentityUser>> GetCurrentUser()
    {
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
        
        // 隐藏敏感信息
        user.PasswordHash = null;
        user.SecurityStamp = null;
        user.ConcurrencyStamp = null;
        // user.RefreshToken = null;
        
        return Ok(user);
    }
    
    /// <summary>
    /// 获取用户信息（仅限管理员）
    /// </summary>
    /// <param name="id">用户ID</param>
    /// <returns>用户信息</returns>
    [HttpGet("{id}")]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public async Task<ActionResult<IdentityUser>> GetUser(string id)
    {
        var user = await _identityService.GetUserByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }
        
        // 隐藏敏感信息
        user.PasswordHash = null;
        user.SecurityStamp = null;
        user.ConcurrencyStamp = null;
        // user.RefreshToken = null;
        
        return Ok(user);
    }
    
    /// <summary>
    /// 更新用户角色（仅限超级管理员）
    /// </summary>
    /// <param name="id">用户ID</param>
    /// <param name="roles">角色列表</param>
    /// <returns>更新结果</returns>
    [HttpPut("{id}/roles")]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> UpdateUserRoles(string id, [FromBody] List<string> roles)
    {
        var result = await _identityService.UpdateUserRolesAsync(id, roles);
        if (!result.Succeeded)
        {
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
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var result = await _identityService.DeleteUserAsync(id);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors });
        }
        
        _logger.LogInformation("用户删除成功，用户ID: {UserId}", id);
        return Ok(new { message = "用户删除成功" });
    }
}
