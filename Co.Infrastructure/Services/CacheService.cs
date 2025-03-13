using System.Text.Json;
using Co.Domain.Interfaces;
using Microsoft.Extensions.Caching.Distributed;

namespace Co.Infrastructure.Services;


/// <summary>
/// Redis缓存服务实现
/// </summary>
public class CacheService : ICacheService
{
    private readonly IDistributedCache _cache;
    private readonly int _defaultCacheTime;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="cache">分布式缓存</param>
    /// <param name="defaultCacheTime">默认缓存时间（分钟）</param>
    public CacheService(IDistributedCache cache, int defaultCacheTime)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _defaultCacheTime = defaultCacheTime;
    }

    /// <summary>
    /// 获取缓存
    /// </summary>
    /// <typeparam name="T">缓存类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <returns>缓存值</returns>
    public async Task<T?> GetAsync<T>(string key)
    {
        var data = await _cache.GetStringAsync(key);
        
        if (string.IsNullOrEmpty(data))
            return default;

        return JsonSerializer.Deserialize<T>(data);
    }

    /// <summary>
    /// 设置缓存
    /// </summary>
    /// <typeparam name="T">缓存类型</typeparam>
    /// <param name="key">缓存键</param>
    /// <param name="value">缓存值</param>
    /// <param name="expirationTime">过期时间（分钟）</param>
    /// <returns>是否成功</returns>
    public async Task<bool> SetAsync<T>(string key, T value, int expirationTime = 0)
    {
        if (value == null)
            return false;

        // 如果没有指定过期时间，使用默认值
        if (expirationTime <= 0)
            expirationTime = _defaultCacheTime;

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(expirationTime)
        };

        string serializedValue = JsonSerializer.Serialize(value);
        
        await _cache.SetStringAsync(key, serializedValue, options);
        return true;
    }

    /// <summary>
    /// 移除缓存
    /// </summary>
    /// <param name="key">缓存键</param>
    /// <returns>是否成功</returns>
    public async Task<bool> RemoveAsync(string key)
    {
        await _cache.RemoveAsync(key);
        return true;
    }
}