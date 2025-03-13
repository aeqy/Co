using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;

namespace Co.WebApi.Controllers;

/// <summary>
/// 调试控制器，用于测试和诊断授权问题
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class DebugController : ControllerBase
{
    private readonly ILogger<DebugController> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="logger">日志记录器</param>
    public DebugController(ILogger<DebugController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// 匿名端点 - 无需授权
    /// </summary>
    [HttpGet("anonymous")]
    [AllowAnonymous]
    public IActionResult GetAnonymous()
    {
        _logger.LogInformation("访问匿名调试端点");
        return Ok(new { message = "匿名访问成功" });
    }

    /// <summary>
    /// 需要OpenIddict授权但无角色要求的端点
    /// </summary>
    [HttpGet("authenticated")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult GetAuthenticated()
    {
        _logger.LogInformation("访问需授权的调试端点");
        
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var userName = User.Identity?.Name;
        
        return Ok(new 
        { 
            message = "授权访问成功", 
            userId = userId,
            userName = userName,
            isAuthenticated = User.Identity?.IsAuthenticated ?? false,
            claims = User.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList()
        });
    }

    /// <summary>
    /// 需要Admin角色的端点
    /// </summary>
    [HttpGet("admin")]
    [Authorize(Roles = "Admin", AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult GetAdminOnly()
    {
        _logger.LogInformation("访问需Admin角色的调试端点");
        
        var roles = User.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type == "role").Select(c => c.Value).ToList();
        var isAdmin = User.IsInRole("Admin");
        
        return Ok(new 
        { 
            message = "Admin角色访问成功", 
            roles = roles,
            isAdmin = isAdmin
        });
    }

    /// <summary>
    /// 需要SuperAdmin角色的端点
    /// </summary>
    [HttpGet("superadmin")]
    [Authorize(Roles = "SuperAdmin", AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult GetSuperAdminOnly()
    {
        _logger.LogInformation("访问需SuperAdmin角色的调试端点");
        
        var roles = User.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type == "role").Select(c => c.Value).ToList();
        var isSuperAdmin = User.IsInRole("SuperAdmin");
        
        return Ok(new 
        { 
            message = "SuperAdmin角色访问成功", 
            roles = roles,
            isSuperAdmin = isSuperAdmin
        });
    }
    
    /// <summary>
    /// 获取当前认证信息（用于调试）
    /// </summary>
    [HttpGet("auth-info")]
    [AllowAnonymous]
    public IActionResult GetAuthInfo()
    {
        _logger.LogInformation("获取认证信息");
        
        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            return Ok(new
            {
                IsAuthenticated = false,
                Message = "用户未认证"
            });
        }
        
        var claims = User.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList();
        var userRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type == "role" || 
                                            c.Type == "roles" || 
                                            c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" ||
                                            c.Type == OpenIddict.Abstractions.OpenIddictConstants.Claims.Role)
                                .Select(c => c.Value)
                                .ToList();
                                
        var roleTypes = claims.Where(c => c.Value == "Admin" || c.Value == "SuperAdmin" || c.Value.Contains("Admin"))
                            .Select(c => c.Type)
                            .Distinct()
                            .ToList();
        
        return Ok(new
        {
            IsAuthenticated = true,
            AuthenticationType = User.Identity.AuthenticationType,
            UserName = User.Identity.Name,
            UserId = User.FindFirstValue(ClaimTypes.NameIdentifier),
            Claims = claims,
            ClaimCount = claims.Count,
            Roles = userRoles,
            RoleClaimTypes = roleTypes,
            StandardChecks = new
            {
                IsInRoleAdmin = User.IsInRole("Admin"),
                IsInRoleSuperAdmin = User.IsInRole("SuperAdmin"),
                HasRoleClaim = claims.Any(c => c.Type == ClaimTypes.Role),
                HasOpenIddictRoleClaim = claims.Any(c => c.Type == OpenIddict.Abstractions.OpenIddictConstants.Claims.Role)
            }
        });
    }
}
