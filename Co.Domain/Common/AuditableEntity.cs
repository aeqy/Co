namespace Co.Domain.Common;

/// <summary>
/// 可审计实体基类，包含创建时间和修改时间
/// </summary>
public abstract class AuditableEntity : EntityBase
{
    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// 创建者
    /// </summary>
    public string? CreatedBy { get; set; }

    /// <summary>
    /// 最后修改时间
    /// </summary>
    public DateTime? LastModified { get; set; }

    /// <summary>
    /// 最后修改者
    /// </summary>
    public string? LastModifiedBy { get; set; }
    
    /// <summary>
    /// 记录创建时间
    /// </summary>
    protected AuditableEntity()
    {
        CreatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// 更新修改时间
    /// </summary>
    /// <param name="modifiedBy"></param>
    public void UpdateModificationInfo(string modifiedBy)
    {
        LastModified = DateTime.UtcNow;
        LastModifiedBy = modifiedBy;
    }
}