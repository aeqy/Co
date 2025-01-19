namespace Co.Domain.Interfaces;

/// <summary>
/// 工作单元接口
/// </summary>
public interface IUnitOfWork : IDisposable
{
    /// <summary>
    /// 获取指定类型的仓储
    /// </summary>
    /// <typeparam name="T">实体类型</typeparam>
    IRepository<T> GetRepository<T>() where T : class;

    /// <summary>
    /// 保存所有更改
    /// </summary>
    Task<int> SaveChangesAsync();

    /// <summary>
    /// 开始事务
    /// </summary>
    Task BeginTransactionAsync();

    /// <summary>
    /// 提交事务
    /// </summary>
    Task CommitTransactionAsync();

    /// <summary>
    /// 回滚事务
    /// </summary>
    Task RollbackTransactionAsync();
}