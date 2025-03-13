using Co.WebApi.Extensions;
using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);


Env.Load(); // 加载 .env 文件

builder.Services.ConfigureServices(builder.Configuration);

var app = builder.Build();

app.Configure();

app.Run();
