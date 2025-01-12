namespace Co.Domain.Common;

/// <summary>
/// 领域事件接口
/// </summary>
public interface IHasDomainEvent
{
    /// <summary>
    /// 领域事件集合
    /// </summary>
    IReadOnlyCollection<DomainEvent> DomainEvents { get; }

    /// <summary>
    /// 清除领域事件
    /// </summary>
    void ClearDomainEvents();
}