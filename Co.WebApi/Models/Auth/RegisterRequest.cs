using System.ComponentModel.DataAnnotations;

namespace Co.WebApi.Models.Auth;

/// <summary>
/// 注册请求模型
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// 邮箱
    /// </summary>
    [Required(ErrorMessage = "邮箱不能为空")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确")]
    [MaxLength(256, ErrorMessage = "邮箱长度不能超过256个字符")]
    public string Email { get; set; } = default!;
    
    /// <summary>
    /// 密码
    /// </summary>
    [Required(ErrorMessage = "密码不能为空")]
    [MinLength(6, ErrorMessage = "密码长度不能少于6个字符")]
    [MaxLength(100, ErrorMessage = "密码长度不能超过100个字符")]
    public string Password { get; set; } = default!;
    
    /// <summary>
    /// 确认密码
    /// </summary>
    [Required(ErrorMessage = "确认密码不能为空")]
    [Compare("Password", ErrorMessage = "两次输入的密码不一致")]
    public string ConfirmPassword { get; set; } = default!;
    
    /// <summary>
    /// 名字
    /// </summary>
    [Required(ErrorMessage = "名字不能为空")]
    [MaxLength(100, ErrorMessage = "名字长度不能超过100个字符")]
    public string FirstName { get; set; } = default!;
    
    /// <summary>
    /// 姓氏
    /// </summary>
    [Required(ErrorMessage = "姓氏不能为空")]
    [MaxLength(100, ErrorMessage = "姓氏长度不能超过100个字符")]
    public string LastName { get; set; } = default!;
    
    /// <summary>
    /// 手机号码
    /// </summary>
    [Phone(ErrorMessage = "手机号码格式不正确")]
    [MaxLength(20, ErrorMessage = "手机号码长度不能超过20个字符")]
    public string? PhoneNumber { get; set; }
}
