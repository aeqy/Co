using Co.Infrastructure.Data;
using Co.WebApi.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureServices(builder.Configuration);

var app = builder.Build();

app.Configure();

await SeedDataService.InitializeDatabaseAsync(app.Services);

app.Run();
