using System.Reflection;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace Co.WebApi.Extensions;

public static class SwaggerServiceExtensions
{
    // 扩展方法：为服务集合添加 Swagger 文档生成服务
    public static IServiceCollection AddSwaggerDocumentation(this IServiceCollection services)
    {
        services.AddSwaggerGen(c =>
        {
            // 配置 Swagger 文档信息
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "MyCc BOM API", // API 标题
                Version = "v1", // API 版本
                Description = "API for managing text entries" // API 描述
            });

            // 启用 XML 注释
            c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory,
                $"{Assembly.GetExecutingAssembly().GetName().Name}.xml"));

            // 启用注解（如果需要）
            // c.EnableAnnotations();

            // 支持多态
            c.UseOneOfForPolymorphism();

            // 自定义排序
            c.OrderActionsBy((apiDesc) =>
                $"Group {apiDesc.GroupName} Action {apiDesc.HttpMethod} {apiDesc.RelativePath}");
        });

        return services; // 返回服务集合以支持链式调用
    }

    // 扩展方法：为应用程序构建器添加 Swagger 中间件
    public static IApplicationBuilder UseSwaggerDocumentation(this IApplicationBuilder app)
    {
        app.UseSwagger(); // 启用 Swagger 中间件，生成 API 文档
        app.UseSwaggerUI(c =>
        {
            // 配置 Swagger UI 页面
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "MyCc API V1"); // 设置 Swagger JSON 端点
            // c.RoutePrefix = string.Empty; // 设置 Swagger UI 在根路径下可用
            c.DocExpansion(DocExpansion.List); // 不自动展开所有 API 操作
            // c.DefaultModelExpandDepth(2); // 设置默认模型展开深度
            c.DefaultModelRendering(ModelRendering.Example); // 设置默认模型渲染方式
            c.DisplayRequestDuration(); // 显示请求持续时间
            // c.ShowExtensions(); // 显示扩展
            // c.DisplayOperationId(); // 显示操作 ID
            c.EnableDeepLinking(); // 启用深链接
        });

        return app; // 返回应用程序构建器以支持链式调用
    }
}