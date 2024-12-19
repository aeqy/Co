namespace Co.WebApi.Extensions;

public static class ApiServiceExtensions
{
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        return services; // 返回服务集合以支持链式调用
    }
}