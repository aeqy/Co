# 开发环境配置示例

## 完整项目架构：添加了测试项目（单元测试和集成测试）
### 目录结构：为每个项目创建了符合DDD和Clean Architecture的文件夹结构
#### 额外工具：
- AutoMapper：对象映射
- FluentValidation：验证逻辑
- Serilog：结构化日志
- JWT认证与授权
- Redis缓存支持
- Dapper：轻量级ORM补充
- 测试环境：
- Moq：模拟测试
- FluentAssertions：友好的断言语法
- AutoFixture：自动生成测试数据
- Docker支持：添加了docker配置占位文件
- 版本控制：添加了基本的gitignore文件

```bash
# 创建解决方案
dotnet new sln -n Co.Solution

# 创建核心项目
dotnet new classlib -n Co.Domain -o Co.Domain
dotnet new classlib -n Co.Application -o Co.Application
dotnet new classlib -n Co.Infrastructure -o Co.Infrastructure
dotnet new webapi -n Co.WebApi -o Co.WebApi

# 创建测试项目
dotnet new xunit -n Co.UnitTests -o Co.UnitTests
dotnet new xunit -n Co.IntegrationTests -o Co.IntegrationTests

# 将项目添加到解决方案
dotnet sln Co.Solution.sln add Co.Domain/Co.Domain.csproj
dotnet sln Co.Solution.sln add Co.Application/Co.Application.csproj
dotnet sln Co.Solution.sln add Co.Infrastructure/Co.Infrastructure.csproj
dotnet sln Co.Solution.sln add Co.WebApi/Co.WebApi.csproj
dotnet sln Co.Solution.sln add Co.UnitTests/Co.UnitTests.csproj
dotnet sln Co.Solution.sln add Co.IntegrationTests/Co.IntegrationTests.csproj

# 设置项目引用关系
dotnet add Co.Application/Co.Application.csproj reference Co.Domain/Co.Domain.csproj
dotnet add Co.Infrastructure/Co.Infrastructure.csproj reference Co.Domain/Co.Domain.csproj
dotnet add Co.Infrastructure/Co.Infrastructure.csproj reference Co.Application/Co.Application.csproj
dotnet add Co.WebApi/Co.WebApi.csproj reference Co.Application/Co.Application.csproj
dotnet add Co.WebApi/Co.WebApi.csproj reference Co.Infrastructure/Co.Infrastructure.csproj
dotnet add Co.UnitTests/Co.UnitTests.csproj reference Co.Domain/Co.Domain.csproj
dotnet add Co.UnitTests/Co.UnitTests.csproj reference Co.Application/Co.Application.csproj
dotnet add Co.IntegrationTests/Co.IntegrationTests.csproj reference Co.WebApi/Co.WebApi.csproj

# Domain 层依赖包
cd Co.Domain
dotnet add package Microsoft.Extensions.DependencyInjection.Abstractions
mkdir Common
mkdir Entities
mkdir Aggregates
mkdir Enums
mkdir Exceptions
mkdir Interfaces
mkdir ValueObjects
cd ..

# Application 层依赖包
cd Co.Application
dotnet add package MediatR
dotnet add package MediatR.Extensions.Microsoft.DependencyInjection
dotnet add package AutoMapper
dotnet add package AutoMapper.Extensions.Microsoft.DependencyInjection
dotnet add package FluentValidation
dotnet add package FluentValidation.DependencyInjectionExtensions
dotnet add package Microsoft.Extensions.Logging.Abstractions
mkdir DTOs
mkdir Interfaces
mkdir Mappings
mkdir Services
mkdir Validators
mkdir Behaviors
mkdir Common
cd ..

# Infrastructure 层依赖包
cd Co.Infrastructure
dotnet add package Microsoft.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
dotnet add package Microsoft.Extensions.Configuration
dotnet add package Microsoft.Extensions.Configuration.Binder
dotnet add package Microsoft.Extensions.Options.ConfigurationExtensions
dotnet add package Microsoft.AspNetCore.Identity
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
dotnet add package Dapper
dotnet add package Serilog
dotnet add package Serilog.AspNetCore
dotnet add package Serilog.Sinks.Console
dotnet add package Serilog.Sinks.File
mkdir Data
mkdir Repositories
mkdir Services
mkdir Identity
mkdir Logging
mkdir Migrations
mkdir Caching
cd ..

# Web API 层依赖包
cd Co.WebApi
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore
dotnet add package Swashbuckle.AspNetCore
dotnet add package Serilog.AspNetCore
dotnet add package Swashbuckle.AspNetCore.Annotations
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package NSwag.AspNetCore
dotnet add package NSwag.MSBuild
dotnet add package Microsoft.AspNetCore.Mvc.NewtonsoftJson
mkdir Controllers
mkdir Filters
mkdir Middlewares
mkdir Models
mkdir Extensions
cd ..

# 单元测试项目依赖包
cd Co.UnitTests
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package Moq
dotnet add package FluentAssertions
dotnet add package AutoFixture
dotnet add package AutoFixture.Xunit2
mkdir Domain
mkdir Application
cd ..

# 集成测试项目依赖包
cd Co.IntegrationTests
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package Microsoft.AspNetCore.Mvc.Testing
dotnet add package FluentAssertions
dotnet add package Respawn
mkdir Api
mkdir Infrastructure
cd ..

# 创建解决方案项目配置目录
mkdir .config
echo "# 开发环境配置示例" > .config/README.md

# 创建Docker相关文件
echo "# Docker Compose配置" > docker-compose.yml
mkdir .docker
echo "# Dockerfile配置" > .docker/Dockerfile

# 创建Git配置文件
echo "bin/\nobj/\n.vs/\n.vscode/\n*.user\nappsettings.Development.json\n*.db\n" > .gitignore

echo "解决方案创建完成，已配置项目依赖关系和推荐的包结构。"

```