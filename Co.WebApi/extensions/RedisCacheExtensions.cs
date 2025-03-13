using Co.Domain.Interfaces;
using Co.Infrastructure.Services;
using Microsoft.Extensions.Caching.Distributed;

namespace Co.WebApi.extensions;

/// <summary>
/// Redis缓存服务扩展类
/// </summary>
public static class RedisCacheExtensions
{
    /// <summary>
    /// 添加Redis缓存服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddRedisCacheServices(this IServiceCollection services, IConfiguration configuration)
    {
        // 获取Redis连接字符串
        var redisConnectionString = configuration.GetConnectionString("Redis");
        
        // 获取Redis设置
        var redisSettings = configuration.GetSection("RedisSettings");
        var instanceName = redisSettings.GetValue<string>("InstanceName");
        var defaultCacheTime = redisSettings.GetValue<int>("DefaultCacheTime");

        // 添加Redis分布式缓存
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = redisConnectionString;
            options.InstanceName = instanceName;
        });

        // 注册自定义缓存服务
        services.AddSingleton<ICacheService>(provider => 
            new CacheService(
                provider.GetRequiredService<IDistributedCache>(),
                defaultCacheTime
            )
        );

        return services;
    }
}