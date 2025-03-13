using System.Collections.Immutable;
using System.Security.Claims;
using Co.Domain.Interfaces;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;


namespace Co.WebApi.Controllers;

/// <summary>
/// 认证控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<AuthController> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    public AuthController(
        IIdentityService identityService,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        ILogger<AuthController> logger)
    {
        _identityService = identityService;
        _userManager = userManager;
        _signInManager = signInManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _logger = logger;
    }

    /// <summary>
    /// 获取Token (OpenIddict token endpoint)
    /// </summary>
    /// <returns>认证结果</returns>
    [HttpPost("token")]
    [Produces("application/json")]
    [AllowAnonymous]
    public async Task<IActionResult> Token()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("OpenID Connect请求不能为空");

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordGrantTypeAsync(request);
        }
        
        if (request.IsRefreshTokenGrantType())
        {
            return await HandleRefreshTokenGrantTypeAsync(request);
        }

        throw new InvalidOperationException($"不支持的授权类型: {request.GrantType}");
    }
    
    /// <summary>
    /// 注册用户
    /// </summary>
    /// <param name="model">注册模型</param>
    /// <returns>注册结果</returns>
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var user = new IdentityUser<Guid>
        {
            UserName = model.Email,
            Email = model.Email,
            // FirstName = model.FirstName,
            // LastName = model.LastName,
            // PhoneNumber = model.PhoneNumber,
            EmailConfirmed = true, // 在生产环境中，应通过邮件确认
            PhoneNumberConfirmed = true // 在生产环境中，应通过短信确认
        };
        
        var result = await _identityService.CreateUserAsync(user, model.Password, new List<string> { "User" });
        
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error);
            }
            
            return BadRequest(ModelState);
        }
        
        _logger.LogInformation("用户 {Email} 注册成功", model.Email);
        return Ok(new { message = "注册成功" });
    }
    
    /// <summary>
    /// 获取当前用户信息
    /// </summary>
    /// <returns>用户信息</returns>
    [HttpGet("userinfo")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "提供的令牌无效"
                }));
        }
        
        var claims = new Dictionary<string, object>();
        
        // 只返回请求的声明
        if (User.HasScope(OpenIddictConstants.Scopes.OpenId))
        {
            claims[OpenIddictConstants.Claims.Subject] = await _userManager.GetUserIdAsync(user);
        }
        
        if (User.HasScope(OpenIddictConstants.Scopes.Profile))
        {
            // claims[OpenIddictConstants.Claims.Name] = user.FullName;
            // claims[OpenIddictConstants.Claims.FamilyName] = user.LastName;
            // claims[OpenIddictConstants.Claims.GivenName] = user.FirstName;
            claims[OpenIddictConstants.Claims.PreferredUsername] = user.UserName;
            // claims[OpenIddictConstants.Claims.UpdatedAt] = user.UpdatedAt?.ToUnixTimeSeconds() ?? user.CreatedAt.ToUnixTimeSeconds();
        }
        
        if (User.HasScope(OpenIddictConstants.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = user.Email;
            claims[OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed;
        }
        
        if (User.HasScope(OpenIddictConstants.Scopes.Phone))
        {
            claims[OpenIddictConstants.Claims.PhoneNumber] = user.PhoneNumber;
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }
        
        if (User.HasScope("roles"))
        {
            claims["roles"] = await _userManager.GetRolesAsync(user);
        }
        
        return Ok(claims);
    }
    
    /// <summary>
    /// 吊销Token
    /// </summary>
    /// <returns>吊销结果</returns>
    [HttpPost("revoke")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> Revoke()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("OpenID Connect请求不能为空");

        // 获取指定的令牌
        var token = request.Token ?? 
            throw new InvalidOperationException("令牌不能为空");

        // 如果刷新令牌，则在用户数据库中将其设为null
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(userId))
        {
            await _identityService.UpdateUserRefreshTokenAsync(userId, null!, DateTime.UtcNow);
        }

        // 让OpenIddict处理吊销逻辑
        return Ok();
    }
    
    #region 私有方法
    
    /// <summary>
    /// 处理密码授权类型
    /// </summary>
    private async Task<IActionResult> HandlePasswordGrantTypeAsync(OpenIddictRequest request)
    {
        // 验证用户名和密码
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user == null)
        {
            _logger.LogWarning("用户名或密码错误，用户名: {Username}", request.Username);
            return Unauthorized(new { error = "invalid_grant", error_description = "用户名或密码错误" });
        }

        // 验证密码
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
            {
                _logger.LogWarning("用户账户被锁定，用户名: {Username}", request.Username);
                return Unauthorized(new { error = "invalid_grant", error_description = "账户被锁定，请稍后再试" });
            }
            
            if (result.IsNotAllowed)
            {
                _logger.LogWarning("用户不允许登录，用户名: {Username}", request.Username);
                return Unauthorized(new { error = "invalid_grant", error_description = "账户未激活，请联系管理员" });
            }
            
            _logger.LogWarning("用户名或密码错误，用户名: {Username}", request.Username);
            return Unauthorized(new { error = "invalid_grant", error_description = "用户名或密码错误" });
        }

        // 更新最后登录信息
        // user.LastLoginTime = DateTime.UtcNow;
        // user.LastLoginIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _userManager.UpdateAsync(user);

        // 创建新的认证票据
        return await CreateAuthenticationTicketAsync(user, request.GetScopes());
    }
    
    /// <summary>
    /// 处理刷新令牌授权类型
    /// </summary>
    private async Task<IActionResult> HandleRefreshTokenGrantTypeAsync(OpenIddictRequest request)
    {
        // 获取现有的刷新令牌验证过的Claims
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result?.Principal == null)
        {
            _logger.LogWarning("刷新令牌验证失败");
            return Unauthorized(new { error = "invalid_grant", error_description = "刷新令牌无效或已过期" });
        }

        // 从Claims中获取用户
        var userId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("刷新令牌不包含用户ID");
            return Unauthorized(new { error = "invalid_grant", error_description = "刷新令牌无效" });
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("刷新令牌对应的用户不存在，用户ID: {UserId}", userId);
            return Unauthorized(new { error = "invalid_grant", error_description = "刷新令牌无效" });
        }

        // 检查用户状态
        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            _logger.LogWarning("用户邮箱未确认，用户ID: {UserId}", userId);
            return Unauthorized(new { error = "invalid_grant", error_description = "账户未激活" });
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            _logger.LogWarning("用户账户被锁定，用户ID: {UserId}", userId);
            return Unauthorized(new { error = "invalid_grant", error_description = "账户被锁定" });
        }

        // 创建新的认证票据
        return await CreateAuthenticationTicketAsync(user, request.GetScopes());
    }
    
    /// <summary>
    /// 创建认证票据
    /// </summary>
    private async Task<IActionResult> CreateAuthenticationTicketAsync(IdentityUser user, ImmutableArray<string> scopes)
    {
        // 获取用户Claims
        var claims = await _identityService.GetUserClaimsAsync(user.Id);
        
        // 添加 scopes 到 claims
        foreach (var scope in scopes)
        {
            claims.Add(new Claim(OpenIddictConstants.Claims.Scope, scope));
        }
        
        // 创建Claims身份
        var identity = new ClaimsIdentity(
            claims,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            ClaimTypes.Name,
            ClaimTypes.Role);

        // 创建Claims主体
        var principal = new ClaimsPrincipal(identity);
        
        // // 设置范围
        // foreach (var scope in scopes)
        // {
        //     principal.SetScope(scope);
        // }
        
        // 设置额外声明资源
        principal.SetResources("api");
        
        // 生成刷新令牌
        if (scopes.Contains(OpenIddictConstants.Scopes.OfflineAccess))
        {
            var refreshToken = Guid.NewGuid().ToString();
            var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(30);
            
            // 存储刷新令牌
            await _identityService.UpdateUserRefreshTokenAsync(user.Id, refreshToken, refreshTokenExpiryTime);
            
            // 设置刷新令牌
            principal.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
        }
        
        // 签发令牌
        var ticket = new AuthenticationTicket(
            principal,
            new AuthenticationProperties(),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        
        // 设置过期时间
        ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1);
        
        // 返回认证结果
        return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
    }
    
    #endregion
}
