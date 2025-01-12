namespace Co.WebApi.Extensions;

public static class RedisExtensions
{
    public static IServiceCollection AddRedisCache(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = configuration.GetConnectionString("Redis");
            options.InstanceName = configuration["RedisSettings:InstanceName"];
        });

        return services;
    }
}