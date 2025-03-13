using System.Security.Claims;
using Co.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Co.WebApi.Controllers;

/// <summary>
/// 测试控制器，用于验证各种功能
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class TestController : ControllerBase
{
    private readonly ICacheService _cacheService;
    private readonly ILogger<TestController> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="cacheService">缓存服务</param>
    /// <param name="logger">日志记录器</param>
    public TestController(ICacheService cacheService, ILogger<TestController> logger)
    {
        _cacheService = cacheService;
        _logger = logger;
    }

    /// <summary>
    /// 公共接口，无需身份验证
    /// </summary>
    /// <returns>测试结果</returns>
    [HttpGet("public")]
    public IActionResult Public()
    {
        return Ok(new { message = "这是一个公共接口，无需身份验证" });
    }

    /// <summary>
    /// 需要身份验证的接口
    /// </summary>
    /// <returns>测试结果</returns>
    [HttpGet("private")]
    [Authorize]
    public IActionResult Private()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = User.FindFirst(ClaimTypes.Name)?.Value;

        return Ok(new 
        { 
            message = "这是一个需要身份验证的接口",
            userId,
            username,
            roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList()
        });
    }

    /// <summary>
    /// 需要管理员角色的接口
    /// </summary>
    /// <returns>测试结果</returns>
    [HttpGet("admin")]
    [Authorize(Roles = "SuperAdmin,Admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new { message = "这是一个需要管理员角色的接口" });
    }

    /// <summary>
    /// 需要超级管理员角色的接口
    /// </summary>
    /// <returns>测试结果</returns>
    [HttpGet("superadmin")]
    [Authorize(Roles = "SuperAdmin")]
    public IActionResult SuperAdminOnly()
    {
        return Ok(new { message = "这是一个需要超级管理员角色的接口" });
    }

    /// <summary>
    /// 测试Redis缓存服务
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <returns>测试结果</returns>
    [HttpGet("cache/{key}")]
    public async Task<IActionResult> TestCache(string key)
    {
        var value = await _cacheService.GetAsync<string>(key);
        if (value == null)
        {
            // 模拟数据
            value = $"缓存值 - {DateTime.Now}";
            
            // 设置缓存，5分钟过期
            await _cacheService.SetAsync(key, value, 5);
            
            return Ok(new { message = "缓存不存在，已创建新缓存", value });
        }
        
        return Ok(new { message = "从缓存中获取值", value });
    }

    /// <summary>
    /// 清除Redis缓存
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <returns>测试结果</returns>
    [HttpDelete("cache/{key}")]
    public async Task<IActionResult> ClearCache(string key)
    {
        var result = await _cacheService.RemoveAsync(key);
        
        return Ok(new { message = result ? "缓存已清除" : "清除缓存失败" });
    }
}
