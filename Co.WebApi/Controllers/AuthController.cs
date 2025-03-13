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
using OpenIddict.Validation.AspNetCore;


namespace Co.WebApi.Controllers;

/// <summary>
/// 认证控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly UserManager<IdentityUser<Guid>> _userManager;
    private readonly SignInManager<IdentityUser<Guid>> _signInManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<AuthController> _logger;

    /// <summary>
    /// 构造函数
    /// </summary>
    public AuthController(
        IIdentityService identityService,
        UserManager<IdentityUser<Guid>> userManager,
        SignInManager<IdentityUser<Guid>> signInManager,
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
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> Userinfo()
    {
        // 添加调试日志
        _logger.LogInformation("User Claims: {Claims}",
            string.Join(", ", User.Claims.Select(c => $"{c.Type}: {c.Value}")));
        _logger.LogInformation("User Identity IsAuthenticated: {IsAuthenticated}", User.Identity?.IsAuthenticated);

        // 直接从声明中获取用户ID
        var userId = User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
                     User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("无法从令牌中提取用户ID");
            return Unauthorized(new { error = "invalid_token", error_description = "提供的令牌无效" });
        }

        // 通过ID查找用户
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("找不到与Token关联的用户，用户ID: {UserId}", userId);
            return Unauthorized(new { error = "invalid_token", error_description = "提供的令牌无效" });
        }

        var claims = new Dictionary<string, object>();

        // 检查令牌的scope声明
        var hasScopes = User.Claims.Any(c => c.Type == OpenIddictConstants.Claims.Scope);
        _logger.LogInformation("Token has scopes: {HasScopes}", hasScopes);
        
        // 始终包含用户ID
        claims[OpenIddictConstants.Claims.Subject] = user.Id.ToString();
        
        // 始终包含基本用户信息
        claims[OpenIddictConstants.Claims.PreferredUsername] = user.UserName;
        
        // 根据声明确定返回的信息
        if (hasScopes && User.HasScope(OpenIddictConstants.Scopes.OpenId))
        {
            // OpenID已包含在基本信息中，无需额外操作
        }

        if (hasScopes && User.HasScope(OpenIddictConstants.Scopes.Profile))
        {
            // claims[OpenIddictConstants.Claims.Name] = user.FullName;
            // claims[OpenIddictConstants.Claims.FamilyName] = user.LastName;
            // claims[OpenIddictConstants.Claims.GivenName] = user.FirstName;
            // claims[OpenIddictConstants.Claims.PreferredUsername] = user.UserName;
            // claims[OpenIddictConstants.Claims.UpdatedAt] = user.UpdatedAt?.ToUnixTimeSeconds() ?? user.CreatedAt.ToUnixTimeSeconds();
        }

        if (hasScopes && User.HasScope(OpenIddictConstants.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = user.Email;
            claims[OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed;
        } else 
        {
            // 始终返回邮箱信息
            claims[OpenIddictConstants.Claims.Email] = user.Email;
            claims[OpenIddictConstants.Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (hasScopes && User.HasScope(OpenIddictConstants.Scopes.Phone))
        {
            claims[OpenIddictConstants.Claims.PhoneNumber] = user.PhoneNumber;
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        } else if (user.PhoneNumber != null)
        {
            // 如果有电话号码，始终返回
            claims[OpenIddictConstants.Claims.PhoneNumber] = user.PhoneNumber;
            claims[OpenIddictConstants.Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
        }

        // 获取用户角色
        var roles = await _userManager.GetRolesAsync(user);
        if (roles != null && roles.Any())
        {
            claims["roles"] = roles;
        }

        return Ok(claims);
    }

    /// <summary>
    /// 吊销Token
    /// </summary>
    /// <returns>吊销结果</returns>
    [HttpPost("revoke")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> Revoke()
    {
        try
        {
            // 获取当前用户ID
            var userId = User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
                         User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("无法从令牌中提取用户ID");
                return Unauthorized(new { error = "invalid_token", error_description = "令牌无效或已过期" });
            }

            // 更新用户刷新令牌为null
            await _identityService.UpdateUserRefreshTokenAsync(userId, null!, DateTime.UtcNow);

            return Ok(new { message = "令牌已成功吊销" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "吊销令牌时发生错误");
            return StatusCode(500, new { error = "server_error", error_description = "吊销令牌时发生错误" });
        }
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
    private async Task<IActionResult> CreateAuthenticationTicketAsync(IdentityUser<Guid> user,
        ImmutableArray<string> scopes)
    {
        try
        {
            _logger.LogInformation("开始为用户 {UserId} 创建认证票据", user.Id);
            // 获取用户Claims
            var claims = await _identityService.GetUserClaimsAsync(user.Id.ToString());

            _logger.LogInformation("获取到用户 {UserId} 的声明 {ClaimsCount} 个", user.Id, claims.Count);

            foreach (var claim in claims)
            {
                _logger.LogInformation("用户 {UserId} 声明: {ClaimType} = {ClaimValue}",
                    user.Id, claim.Type, claim.Value);
            }

            // 确保包含 subject claim - 这是 OpenIddict 强制要求的
            if (!claims.Any(c => c.Type == OpenIddictConstants.Claims.Subject))
            {
                _logger.LogInformation("为用户 {UserId} 添加缺失的Subject声明", user.Id);
                claims.Add(new Claim(OpenIddictConstants.Claims.Subject, user.Id.ToString()));
            }

            // 获取用户角色并添加到claims中
            var roles = await _userManager.GetRolesAsync(user);
            _logger.LogInformation("用户 {UserId} 拥有的角色: {Roles}",
                user.Id, string.Join(", ", roles));

            foreach (var role in roles)
            {
                _logger.LogInformation("为用户 {UserId} 添加角色声明: {Role}", user.Id, role);
                claims.Add(new Claim(ClaimTypes.Role, role));
                // 同时添加OpenIddict标准格式的角色声明
                claims.Add(new Claim("role", role));
                // 再添加一种可能的格式
                claims.Add(new Claim(OpenIddictConstants.Claims.Role, role));
            }

            // 添加 scopes 到 claims
            foreach (var scope in scopes)
            {
                _logger.LogInformation("为用户 {UserId} 添加Scope声明: {Scope}", user.Id, scope);
                claims.Add(new Claim(OpenIddictConstants.Claims.Scope, scope));
            }

            // 创建Claims身份
            var identity = new ClaimsIdentity(
                claims,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                ClaimTypes.Name,
                ClaimTypes.Role);

            _logger.LogInformation("为用户 {UserId} 创建的ClaimsIdentity使用名称类型: {NameType}，角色类型: {RoleType}",
                user.Id, identity.NameClaimType, identity.RoleClaimType);

            // 创建Claims主体
            var principal = new ClaimsPrincipal(identity);


            // 设置额外声明资源
            principal.SetResources("api");
            _logger.LogInformation("为用户 {UserId} 设置资源: api", user.Id);

            // 生成刷新令牌
            if (scopes.Contains(OpenIddictConstants.Scopes.OfflineAccess))
            {
                var refreshToken = Guid.NewGuid().ToString();
                var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(30);

                _logger.LogInformation("为用户 {UserId} 生成刷新令牌，过期时间: {ExpiryTime}",
                    user.Id, refreshTokenExpiryTime);

                // 存储刷新令牌
                await _identityService.UpdateUserRefreshTokenAsync(user.Id.ToString(), refreshToken,
                    refreshTokenExpiryTime);

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
            _logger.LogInformation("为用户 {UserId} 的认证票据设置过期时间: {ExpiryTime}",
                user.Id, ticket.Properties.ExpiresUtc);

            // 返回认证结果
            _logger.LogInformation("成功完成用户 {UserId} 的认证票据创建", user.Id);
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建认证票据时发生错误: {ErrorMessage}", ex.Message);
            throw;
        }

        #endregion
    }
}