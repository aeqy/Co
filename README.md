# Clean Architecture


#### 数据库连接说明

- ##### 数据库连接配置在 appsettings.json 文件中

```base
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Username=postgres;Password=密码;Database=PGSql数据库名称"
  },
}
```

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
### 项目结构

```text

Co.Solution/          (解决方案根目录)
├── Co.WebApi/        (Web API 项目 - 表现层)
│   ├── Controllers/    (控制器)
│   │   └── ProductsController.cs
│   ├── appsettings.json (配置文件)
│   ├── Program.cs      (程序入口和配置)
│   └── Co.WebApi.csproj
├── Co.Domain/         (领域层 - 核心业务逻辑)
│   ├── Entities/       (实体类)
│   │   └── Product.cs
│   ├── Interfaces/     (领域接口 - 可选)
│   │   └── IProductRepository.cs
│   └── Co.Domain.csproj
├── Co.Application/    (应用层 - 用例和业务流程)
│   ├── Products/       (产品相关的用例)
│   │   ├── Queries/     (查询)
│   │   │   ├── GetProductsQuery.cs
│   │   │   └── GetProductsQueryHandler.cs
│   │   ├── Commands/    (命令)
│   │   │   ├── CreateProductCommand.cs
│   │   │   └── CreateProductCommandHandler.cs
│   │   └── Validations/(验证 - 可选)
│   ├── AssemblyReference.cs (程序集引用，用于MediatR注册)
│   └── Co.Application.csproj
├── Co.Infrastructure/   (基础设施层 - 数据访问、外部服务等)
│   ├── Persistence/   (持久化 - 数据库访问)
│   │   └── ApplicationDbContext.cs
│   ├── Repositories/   (仓储实现 - 可选)
│   │   └── ProductRepository.cs
│   └── Co.Infrastructure.csproj
└── Co.Solution.sln

```

## 目录和文件说明

```text

Co.Solution/ (解决方案根目录):

Co.Solution.sln: 解决方案文件，包含所有项目。
Co.WebApi/ (Web API 项目 - 表现层):

Controllers/: 包含处理 HTTP 请求的控制器。
ProductsController.cs: 处理与产品相关的 HTTP 请求。
appsettings.json: 应用程序配置文件，包含数据库连接字符串、日志配置等。
Program.cs: 应用程序的入口点，负责配置服务、中间件和路由。
Co.WebApi.csproj: Web API 项目文件。
Co.Domain/ (领域层 - 核心业务逻辑):

Entities/: 包含领域实体类，代表业务概念。
Product.cs: 产品实体类。
Interfaces/: (可选) 包含领域接口，定义领域模型的操作。
IProductRepository.cs: 产品仓储接口。
Co.Domain.csproj: 领域层项目文件。
Co.Application/ (应用层 - 用例和业务流程):

Products/: 包含与产品相关的用例。
Queries/: 包含查询用例和处理程序。
GetProductsQuery.cs: 获取产品列表的查询。
GetProductsQueryHandler.cs: 处理获取产品列表的查询。
Commands/: 包含命令用例和处理程序。
CreateProductCommand.cs: 创建产品的命令。
CreateProductCommandHandler.cs: 处理创建产品的命令。
Validations/: (可选) 包含验证规则。
AssemblyReference.cs: 一个空的类，用于 MediatR 的程序集扫描。
Co.Application.csproj: 应用层项目文件。
Co.Infrastructure/ (基础设施层 - 数据访问、外部服务等):

Persistence/: 包含与持久化相关的类。
ApplicationDbContext.cs: Entity Framework Core 的 DbContext，负责数据库连接和模型映射。
Repositories/: (可选) 包含仓储模式的实现。
ProductRepository.cs: 产品仓储的实现。
Co.Infrastructure.csproj: 基础设施层项目文件。


```

### 说明和最佳实践

```text

分层架构： 该项目采用了分层架构，将不同的职责划分为不同的层，提高了代码的可维护性、可测试性和可扩展性。
领域驱动设计 (DDD) 概念： Co.Domain 层体现了 DDD 的核心思想，专注于业务领域模型。
CQRS (Command Query Responsibility Segregation): Co.Application 层中的 Queries 和 Commands 目录体现了 CQRS 的思想，将读操作和写操作分离。
MediatR： 使用 MediatR 实现请求/响应模式，解耦了请求发送者和处理者。
依赖倒置原则： 高层模块不应该依赖于低层模块，它们都应该依赖于抽象。例如，Co.Application 依赖于 Co.Domain 中定义的接口，而不是 Co.Infrastructure 中的具体实现。
可测试性： 分层架构和依赖倒置原则使得代码更容易进行单元测试和集成测试。
可选目录和文件


 Co.Domain/Interfaces/: 如果使用了仓储模式或其他领域服务，建议创建 Interfaces 目录来定义接口。
 Co.Application/Validations/: 如果需要对命令或查询进行验证，可以在 Validations 目录中添加验证规则。
 Co.Infrastructure/Repositories/: 如果需要使用仓储模式，可以在 Repositories 目录中实现仓储接口。

```


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
