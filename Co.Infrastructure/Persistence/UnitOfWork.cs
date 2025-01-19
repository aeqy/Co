using Co.Domain.Interfaces;
using Co.Infrastructure.Data;
using Microsoft.EntityFrameworkCore.Storage;

namespace Co.Infrastructure.Persistence;

/// <summary>
/// 工作单元实现
/// </summary>
public class UnitOfWork : IUnitOfWork
{
    private readonly CoDbContext _context;
    private IDbContextTransaction _transaction;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="context">数据库上下文</param>
    public UnitOfWork(CoDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// 获取指定类型的仓储
    /// </summary>
    public IRepository<T> GetRepository<T>() where T : class
    {
        return new Repository<T>(_context);
    }

    /// <summary>
    /// 保存所有更改
    /// </summary>
    public async Task<int> SaveChangesAsync()
    {
        return await _context.SaveChangesAsync();
    }

    /// <summary>
    /// 开始事务
    /// </summary>
    public async Task BeginTransactionAsync()
    {
        _transaction = await _context.Database.BeginTransactionAsync();
    }

    /// <summary>
    /// 提交事务
    /// </summary>
    public async Task CommitTransactionAsync()
    {
        if (_transaction != null)
        {
            await _transaction.CommitAsync();
            await _transaction.DisposeAsync();
            _transaction = null;
        }
    }

    /// <summary>
    /// 回滚事务
    /// </summary>
    public async Task RollbackTransactionAsync()
    {
        if (_transaction != null)
        {
            await _transaction.RollbackAsync();
            await _transaction.DisposeAsync();
            _transaction = null;
        }
    }

    /// <summary>
    /// 释放资源
    /// </summary>
    public void Dispose()
    {
        _context.Dispose();
        GC.SuppressFinalize(this);
    }
}
