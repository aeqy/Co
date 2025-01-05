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
```## 项目结构

```
Co.Solution/
├── Co.WebApi/          # 表示层/API层
├── Co.Application/     # 应用层
├── Co.Domain/          # 领域层
├── Co.Infrastructure/  # 基础设施层
```

## 技术栈

### 核心依赖
- **依赖注入**: Microsoft.Extensions.DependencyInjection
- **事件总线**: MediatR
- **ORM**: Entity Framework Core
- **数据库**: PostgreSQL
- **缓存**: Redis (StackExchange.Redis)
- **消息队列**: RabbitMQ/Kafka
- **日志**: Serilog
- **认证授权**: OpenIddict
- **API文档**: Swashbuckle/Swagger
- **健康检查**: ASP.NET Core Health Checks
- **对象映射**: AutoMapper
- **验证**: FluentValidation

## 架构模式

### 清洁架构
- **表示层**: 处理HTTP请求/响应，认证授权
- **应用层**: 实现用例，CQRS模式
- **领域层**: 包含业务逻辑，实体，值对象
- **基础设施层**: 实现持久化，外部服务

### 领域驱动设计
- 实体和值对象
- 聚合和聚合根
- 领域服务
- 领域事件
- 规约模式

## 实现细节

### 基础设施层
- **持久化**: 使用Entity Framework Core和PostgreSQL
- **缓存**: 使用StackExchange.Redis实现Redis缓存
- **消息队列**: RabbitMQ/Kafka集成
- **工作单元**: 自定义事务管理实现
- **仓储**: 使用规约模式的通用仓储实现

### 应用层
- **CQRS模式**: 分离命令和查询
- **应用服务**: 编排领域逻辑
- **DTO**: API契约的数据传输对象
- **验证**: 使用FluentValidation进行输入验证
- **事件处理**: 使用MediatR处理领域和应用事件

### 领域层
- **实体**: 具有标识的核心业务对象
- **值对象**: 没有标识的不可变对象
- **聚合**: 具有聚合根的一致性边界
- **领域服务**: 跨多个实体的业务逻辑
- **规约**: 业务规则的封装

### 表示层
- **控制器**: RESTful API端点
- **认证授权**: 使用OpenIddict实现OAuth2/OpenID Connect
- **文档**: Swagger/OpenAPI文档
- **健康检查**: 系统监控端点
- **异常处理**: 全局异常中间件

### 提交类型标签

可以在提交信息中使用标签来标识提交的类型，常见的标签包括：

- `feat`：新功能
- `fix`：修复bug
- `docs`：文档更新
- `style`：代码格式（不影响代码运行的变动）
- `refactor`：重构（即不是新增功能，也不是修复bug的代码变动）
- `test`：增加测试
- `chore`：构建过程或辅助工具的变动

通过遵循这些规范，可以提高代码库的可读性和可维护性，帮助团队更有效地协作。
