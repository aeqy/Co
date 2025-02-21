# Co
Clean Architecture


## 完整项目创建命令集

```bash
# 创建解决方案
dotnet new sln -n Co.Solution &&

# 创建项目
dotnet new webapi -n Co.WebApi -o Co.WebApi &&
dotnet new classlib -n Co.Domain -o Co.Domain &&
dotnet new classlib -n Co.Infrastructure -o Co.Infrastructure &&
dotnet new classlib -n Co.Application -o Co.Application &&

# 将项目添加到解决方案
dotnet sln Co.Solution.sln add Co.WebApi/Co.WebApi.csproj Co.Domain/Co.Domain.csproj Co.Infrastructure/Co.Infrastructure.csproj Co.Application/Co.Application.csproj &&

# 安装 Web API 项目的依赖包
cd Co.WebApi &&
dotnet add package Swashbuckle.AspNetCore &&
dotnet add package Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore &&
dotnet add reference ../Co.Application/Co.Application.csproj &&
dotnet add reference ../Co.Infrastructure/Co.Infrastructure.csproj &&
cd .. &&

# 安装基础设施层项目的依赖包
cd Co.Infrastructure &&
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL &&
dotnet add package Microsoft.EntityFrameworkCore &&
dotnet add package Microsoft.EntityFrameworkCore.Relational &&
dotnet add package Microsoft.EntityFrameworkCore.Design &&
dotnet add package Microsoft.EntityFrameworkCore.Tools &&
dotnet add reference ../Co.Domain/Co.Domain.csproj &&
cd .. &&

# 安装应用层项目的依赖包
cd Co.Application &&
dotnet add package MediatR &&
dotnet add package MediatR.Extensions.Microsoft.DependencyInjection &&
dotnet add reference ../Co.Domain/Co.Domain.csproj &&
cd ..

```

---
### 使用说明
- 运行方式：将以上命令集复制到终端中，直接粘贴并按回车键运行即可。
  命令连接：使用 && 连接所有命令，确保每个命令按顺序执行，前一个命令成功完成后才会执行下一个。
## 功能概览：
- 创建一个名为 Co.Solution 的解决方案。
- 创建四个项目：Co.WebApi（Web API 项目）、Co.Domain（领域层）、Co.Infrastructure（基础设施层）、Co.Application（应用层）。
- 为每个项目安装常用 NuGet 包，例如 Swagger（API 文档）、Entity Framework Core（数据库支持）、MediatR（CQRS 模式支持）等。
- 设置项目之间的引用关系，确保层级结构清晰。


## 项目启动

```bash
#在 Co.Infrastructure

 dotnet ef migrations add InitialCreate
 
 #登陆Token接口
 
  grant_type:password
  username:admin
  password:Admin@123
  scope:openid
  client_id:my-client
  client_secret:your-client-secret

```
---
## Git提交注意事项

```
feat 增加新功能
fix 修复问题/BUG
style 代码风格相关无影响运行结果的
perf 优化/性能提升
refactor 重构
revert 撤销修改
test 测试相关
docs 文档/注释
chore 依赖更新/脚手架配置修改等
workflow 工作流改进
ci 持续集成
types 类型修改
```