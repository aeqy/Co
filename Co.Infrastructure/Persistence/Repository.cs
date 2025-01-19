using System.Linq.Expressions;
using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Co.Infrastructure.Persistence;

/// <summary>
/// 通用仓储实现
/// </summary>
/// <typeparam name="T">实体类型</typeparam>
public class Repository<T> : IRepository<T> where T : class
{
    private readonly CoDbContext _context;
    private readonly DbSet<T> _dbSet;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="context">数据库上下文</param>
    public Repository(CoDbContext context)
    {
        _context = context;
        _dbSet = _context.Set<T>();
    }

    /// <summary>
    /// 获取所有实体
    /// </summary>
    public IQueryable<T> GetAll()
    {
        return _dbSet.AsNoTracking();
    }

    /// <summary>
    /// 根据条件获取实体
    /// </summary>
    public IQueryable<T> GetByCondition(Expression<Func<T, bool>> predicate)
    {
        return _dbSet.Where(predicate).AsNoTracking();
    }

    /// <summary>
    /// 根据ID获取实体
    /// </summary>
    public async Task<T> GetByIdAsync(object id)
    {
        return await _dbSet.FindAsync(id);
    }

    /// <summary>
    /// 添加实体
    /// </summary>
    public async Task AddAsync(T entity)
    {
        await _dbSet.AddAsync(entity);
    }

    /// <summary>
    /// 更新实体
    /// </summary>
    public void Update(T entity)
    {
        _dbSet.Attach(entity);
        _context.Entry(entity).State = EntityState.Modified;
    }

    /// <summary>
    /// 删除实体
    /// </summary>
    public void Delete(T entity)
    {
        if (_context.Entry(entity).State == EntityState.Detached)
        {
            _dbSet.Attach(entity);
        }
        _dbSet.Remove(entity);
    }

    /// <summary>
    /// 根据条件删除实体
    /// </summary>
    public async Task DeleteAsync(Expression<Func<T, bool>> predicate)
    {
        var entities = await _dbSet.Where(predicate).ToListAsync();
        _dbSet.RemoveRange(entities);
    }

    /// <summary>
    /// 判断是否存在
    /// </summary>
    public async Task<bool> ExistsAsync(Expression<Func<T, bool>> predicate)
    {
        return await _dbSet.AnyAsync(predicate);
    }
}
