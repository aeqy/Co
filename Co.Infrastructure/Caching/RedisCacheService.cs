using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace Co.Infrastructure.Caching;

public class RedisCacheService(IDistributedCache cache) : ICacheService
{
    public async Task<T> GetAsync<T>(string key)
    {
        var value = await cache.GetStringAsync(key);
        return value == null ? default : JsonSerializer.Deserialize<T>(value);
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiry = null)
    {
        var options = new DistributedCacheEntryOptions();
        if (expiry.HasValue)
        {
            options.SetAbsoluteExpiration(expiry.Value);
        }
            
        await cache.SetStringAsync(key, JsonSerializer.Serialize(value), options);
    }

    public async Task RemoveAsync(string key)
    {
        await cache.RemoveAsync(key);
    }

    public async Task<bool> ExistsAsync(string key)
    {
        var value = await cache.GetStringAsync(key);
        return value != null;
    }

    public async Task ClearAsync()
    {
        // Redis不支持直接清空所有缓存，需要手动实现
        // 这里可以结合Redis的keys命令实现，但生产环境不推荐
        throw new NotImplementedException("Redis does not support clearing all cache directly");
    }
}