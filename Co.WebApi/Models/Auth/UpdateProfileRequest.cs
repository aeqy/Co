using System.ComponentModel.DataAnnotations;

namespace Co.WebApi.Models.Auth;

/// <summary>
/// 更新用户资料请求模型
/// </summary>
public class UpdateProfileRequest
{
    /// <summary>
    /// 名字
    /// </summary>
    [Required(ErrorMessage = "名字不能为空")]
    [MaxLength(100, ErrorMessage = "名字长度不能超过100个字符")]
    public string FirstName { get; set; } = null!;
    
    /// <summary>
    /// 姓氏
    /// </summary>
    [Required(ErrorMessage = "姓氏不能为空")]
    [MaxLength(100, ErrorMessage = "姓氏长度不能超过100个字符")]
    public string LastName { get; set; } = null!;
    
    /// <summary>
    /// 手机号码
    /// </summary>
    [Phone(ErrorMessage = "手机号码格式不正确")]
    [MaxLength(20, ErrorMessage = "手机号码长度不能超过20个字符")]
    public string? PhoneNumber { get; set; }
}
