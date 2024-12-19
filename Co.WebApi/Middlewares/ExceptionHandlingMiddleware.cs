using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace Co.WebApi.Middlewares;

public class ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        var response = context.Response;
        response.ContentType = "application/json";

        // 设置默认状态码为 InternalServerError
        var statusCode = HttpStatusCode.InternalServerError;

        // 记录详细的错误信息
        logger.LogError(exception, $"发生未处理的异常：{context.Request.Path} {context.Request.Method}");

        switch (exception)
        {
            case ApplicationException:
                statusCode = HttpStatusCode.BadRequest;
                break;
            case KeyNotFoundException:
                statusCode = HttpStatusCode.NotFound;
                break;
        }

        response.StatusCode = (int)statusCode;

        // 使用 ProblemDetails 来标准化错误响应
        var problemDetails = new ProblemDetails
        {
            Status = (int)statusCode,
            Title = "An error occurred while processing your request.",
            Detail = exception.Message
        };

        var result = JsonSerializer.Serialize(problemDetails);
        await response.WriteAsync(result);
    }
}