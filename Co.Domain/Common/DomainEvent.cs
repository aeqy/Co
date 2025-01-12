namespace Co.Domain.Common;

/// <summary>
/// 领域事件基类
/// </summary>
public abstract class DomainEvent
{
    /// <summary>
    /// 事件发生时间
    /// </summary>
    public DateTime OccurredOn { get; protected set; } = DateTime.UtcNow;

    /// <summary>
    /// 事件ID
    /// </summary>
    public Guid EventId { get; } = Guid.NewGuid();
}