using Co.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Co.WebApi.Controllers;

/// <summary>
/// 角色控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "SuperAdmin,Admin")]
public class RolesController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly ILogger<RolesController> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="identityService">身份服务</param>
    /// <param name="logger">日志记录器</param>
    public RolesController(IIdentityService identityService, ILogger<RolesController> logger)
    {
        _identityService = identityService;
        _logger = logger;
    }
    
    /// <summary>
    /// 获取所有角色
    /// </summary>
    /// <returns>角色列表</returns>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<IdentityRole>>> GetRoles()
    {
        var roles = await _identityService.GetAllRolesAsync();
        return Ok(roles);
    }
    
    /// <summary>
    /// 创建角色
    /// </summary>
    /// <param name="role">角色</param>
    /// <returns>创建结果</returns>
    [HttpPost]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> CreateRole(IdentityRole<Guid> role)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var result = await _identityService.CreateRoleAsync(role);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error);
            }
            
            return BadRequest(ModelState);
        }
        
        _logger.LogInformation("角色创建成功，角色名: {RoleName}", role.Name);
        return Ok(new { message = "角色创建成功" });
    }
    
    /// <summary>
    /// 删除角色
    /// </summary>
    /// <param name="id">角色ID</param>
    /// <returns>删除结果</returns>
    [HttpDelete("{id}")]
    [Authorize(Roles = "SuperAdmin")]
    public async Task<IActionResult> DeleteRole(string id)
    {
        var result = await _identityService.DeleteRoleAsync(id);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors });
        }
        
        _logger.LogInformation("角色删除成功，角色ID: {RoleId}", id);
        return Ok(new { message = "角色删除成功" });
    }
}
