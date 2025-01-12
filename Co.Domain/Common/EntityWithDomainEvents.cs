using System.Collections.ObjectModel;

namespace Co.Domain.Common;

/// <summary>
/// 领域事件基类实现
/// </summary>
public abstract class EntityWithDomainEvents : IHasDomainEvent
{
    private readonly List<DomainEvent> _domainEvents = new();

    /// <summary>
    /// 领域事件集合
    /// </summary>
    public IReadOnlyCollection<DomainEvent> DomainEvents => new ReadOnlyCollection<DomainEvent>(_domainEvents);

    /// <summary>
    /// 添加领域事件
    /// </summary>
    /// <param name="domainEvent">领域事件</param>
    protected void AddDomainEvent(DomainEvent domainEvent)
    {
        _domainEvents.Add(domainEvent);
    }

    /// <summary>
    /// 清除领域事件
    /// </summary>
    public void ClearDomainEvents()
    {
        _domainEvents.Clear();
    }
}