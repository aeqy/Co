# Clean Architecture



- #### 创建项目结构

```Bash

dotnet new sln -n Co.Solution
dotnet new webapi -n Co.WebApi -o Co.WebApi
dotnet new classlib -n Co.Domain -o Co.Domain
dotnet new classlib -n Co.Infrastructure -o Co.Infrastructure
dotnet new classlib -n Co.Application -o Co.Application
dotnet sln Co.Solution.sln add Co.WebApi/Co.WebApi.csproj Co.Domain/Co.Domain.csproj Co.Infrastructure/Co.Infrastructure.csproj Co.Application/Co.Application.csproj

cd Co.WebApi
dotnet add package Microsoft.EntityFrameworkCore.Design Swashbuckle.AspNetCore Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore Npgsql.EntityFrameworkCore.PostgreSQL Microsoft.EntityFrameworkCore.Tools
dotnet add reference ../Co.Application ../Co.Infrastructure
cd ../Co.Infrastructure
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL Microsoft.EntityFrameworkCore Microsoft.EntityFrameworkCore.Relational Microsoft.Extensions.Configuration.Abstractions
dotnet add reference ../Co.Domain
cd ../Co.Application
dotnet add package MediatR MediatR.Extensions.Microsoft.DependencyInjection
dotnet add reference ../Co.Domain
cd ..

```
---

#### 数据库连接说明

- ##### 数据库连接配置在 appsettings.json 文件中

```base
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Username=postgres;Password=密码;Database=PGSql数据库名称"
  },
}
```