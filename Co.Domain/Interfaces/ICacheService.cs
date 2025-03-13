namespace Co.Domain.Interfaces;

/// <summary>
/// Redis缓存服务接口
/// </summary>
public interface ICacheService
{
    /// <summary>
    /// 获取缓存
    /// </summary>
    /// <typeparam name="T">缓存类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <returns>缓存值</returns>
    Task<T?> GetAsync<T>(string key);

    /// <summary>
    /// 设置缓存
    /// </summary>
    /// <typeparam name="T">缓存类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <param name="value">缓存值</param>
    /// <param name="expirationTime">过期时间（分钟）</param>
    /// <returns>是否成功</returns>
    Task<bool> SetAsync<T>(string key, T value, int expirationTime = 60);

    /// <summary>
    /// 移除缓存
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <returns>是否成功</returns>
    Task<bool> RemoveAsync(string key);
}