using Co.Infrastructure.Caching;
using Co.Infrastructure.Data;
using Co.WebApi.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureServicesDatabase(builder.Configuration); // Configure Database

builder.Services.AddOpenIddictServer(); // Add OpenIddict Server

builder.Services.AddJwtAuthorization(); // Add JWT Authorization

builder.Services.AddControllers(); // Add Controllers

builder.Services.AddSwaggerDocumentation(); // Add Swagger Documentation

builder.Logging.ClearProviders(); // Clear Logging Providers

builder.Logging.AddConsole(); // Add Console Logging Provider

builder.Services.AddApiServices(builder.Configuration); // Add Api Services

builder.Services.AddScoped<SeedDataService>(); // Add Seed Data Service

builder.Services.AddRedisCache(builder.Configuration);

builder.Services.AddScoped<ICacheService, RedisCacheService>();


var app = builder.Build();

await app.SeedDatabaseAsync(); // Seed Database

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwaggerDocumentation(); // Add Swagger Documentation
}

app.UseDefaultFiles(); // Use Default Files
app.UseStaticFiles(); // Use Static Files
app.UseAuthentication(); // Use Authentication
app.UseAuthorization(); // Use Authorization
app.MapControllers(); // Map Controllers
app.UseRouting(); // Use Routing
app.UseHttpsRedirection(); // Use Https Redirection

app.Run();