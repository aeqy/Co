namespace Co.WebApi.Extensions;

public static class ApiServiceExtensions
{
    /// <summary>
    /// 添加应用服务层和基础设施层的依赖注入
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        
        return services; // 返回服务集合以支持链式调用
    }
}