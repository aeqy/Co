using System.ComponentModel.DataAnnotations;

namespace Co.WebApi.Models.Auth;

/// <summary>
/// 登录请求模型
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// 用户名/邮箱
    /// </summary>
    [Required(ErrorMessage = "用户名不能为空")]
    [MaxLength(256, ErrorMessage = "用户名长度不能超过256个字符")]
    public string Username { get; set; } = default!;
    
    /// <summary>
    /// 密码
    /// </summary>
    [Required(ErrorMessage = "密码不能为空")]
    [MaxLength(100, ErrorMessage = "密码长度不能超过100个字符")]
    public string Password { get; set; } = default!;
    
    /// <summary>
    /// 记住我
    /// </summary>
    public bool RememberMe { get; set; }
}
