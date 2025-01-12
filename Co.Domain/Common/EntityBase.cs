namespace Co.Domain.Common;

/// <summary>
/// 实体基类
/// </summary>
public abstract class EntityBase : EntityWithDomainEvents
{
    /// <summary>
    /// 实体ID
    /// </summary>
    public Guid Id { get; protected set; } = Guid.NewGuid();
}