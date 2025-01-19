using System.Linq.Expressions;

namespace Co.Domain.Interfaces;

/// <summary>
/// 通用仓储接口
/// </summary>
/// <typeparam name="T">实体类型</typeparam>
public interface IRepository<T> where T : class
{
    /// <summary>
    /// 获取所有实体
    /// </summary>
    IQueryable<T> GetAll();

    /// <summary>
    /// 根据条件获取实体
    /// </summary>
    /// <param name="predicate">查询条件</param>
    IQueryable<T> GetByCondition(Expression<Func<T, bool>> predicate);

    /// <summary>
    /// 根据ID获取实体
    /// </summary>
    /// <param name="id">实体ID</param>
    Task<T> GetByIdAsync(object id);

    /// <summary>
    /// 添加实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    Task AddAsync(T entity);

    /// <summary>
    /// 更新实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    void Update(T entity);

    /// <summary>
    /// 删除实体
    /// </summary>
    /// <param name="entity">实体对象</param>
    void Delete(T entity);

    /// <summary>
    /// 根据条件删除实体
    /// </summary>
    /// <param name="predicate">删除条件</param>
    Task DeleteAsync(Expression<Func<T, bool>> predicate);

    /// <summary>
    /// 判断是否存在
    /// </summary>
    /// <param name="predicate">查询条件</param>
    Task<bool> ExistsAsync(Expression<Func<T, bool>> predicate);
}
