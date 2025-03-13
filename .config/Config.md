# 项目配置文件说明 (README)

本文档描述了项目的配置文件内容，包括数据库连接、身份验证选项、JWT 配置、Redis 设置等关键参数。以下是详细说明：

---
## 配置内容

### 1. 种子数据 (SeedData)
用于初始化项目的种子数据配置：
- **SeedRoles**: `true` - 是否种子化角色数据
- **SeedUsers**: `true` - 是否种子化用户数据
- **SeedOpenIddict**: `true` - 是否种子化 OpenIddict 数据
- **AdminPassword**: `YourAdminPassword` - 管理员默认密码
- **UserPassword**: `YourUserPassword` - 用户默认密码
- **OpenIddict**:
    - **SpaClientSecret**: `spa-client-secret` - SPA 客户端密钥
    - **ServiceClientSecret**: `service-client-secret` - 服务客户端密钥
    - **PasswordClientSecret**: `password-client-secret` - 密码客户端密钥

### 2. 连接字符串 (ConnectionStrings)
数据库和缓存的连接信息：
- **DefaultConnection**: PostgreSQL 数据库连接字符串
    - 主机: `postgres.co.orb.local`
    - 端口: `5432`
    - 数据库: `co_db`
    - 用户名: `prod_user`
    - 密码: `wthVHzZypXiRQHj/NTTO4w==` (已加密)
- **Redis**: Redis 连接字符串
    - 地址: `redis:6379`
    - 密码: `cS+V02TzClHoPYWyKOBXPQ==` (已加密)

### 3. Redis 设置 (RedisSettings)
Redis 缓存的配置：
- **InstanceName**: `Co_` - Redis 实例名称前缀
- **DefaultCacheTime**: `60` - 默认缓存时间（单位：分钟）

### 4. 身份选项 (IdentityOptions)
用户身份验证相关的规则：
- **Password**: 密码要求
    - **RequireDigit**: `true` - 必须包含数字
    - **RequireLowercase**: `true` - 必须包含小写字母
    - **RequireUppercase**: `true` - 必须包含大写字母
    - **RequireNonAlphanumeric**: `true` - 必须包含非字母数字字符
    - **RequiredLength**: `8` - 最小密码长度为 8 个字符
- **User**: 用户设置
    - **RequireUniqueEmail**: `true` - 要求用户邮箱唯一
- **Lockout**: 锁定设置
    - **DefaultLockoutTimeSpan**: `00:05:00` - 默认锁定时间为 5 分钟
    - **MaxFailedAccessAttempts**: `5` - 最大失败登录尝试次数为 5 次
    - **AllowedForNewUsers**: `true` - 新用户允许使用锁定功能

### 5. JWT 选项 (JwtOptions)
JSON Web Token (JWT) 的配置：
- **Secret**: `your-very-long-and-secure-secret-key-here` - JWT 密钥（需足够长且安全）
- **Issuer**: `https://localhost:7028` - 发行者地址
- **Audience**: `api` - 受众（API）
- **AccessTokenExpiration**: `60` - 访问令牌过期时间（单位：分钟）
- **RefreshTokenExpiration**: `1440` - 刷新令牌过期时间（单位：分钟，相当于 24 小时）

### 6. 认证设置 (Authentication)
- **Authority**: `https://localhost:7179` - 认证服务的权威地址

### 7. OpenIddict 设置 (OpenIddict)
OpenIddict 身份验证端点配置：
- **TokenEndpoint**: `/connect/token` - 令牌端点
- **AuthorizationEndpoint**: `/connect/authorize` - 授权端点
- **UserInfoEndpoint**: `/connect/userinfo` - 用户信息端点

### 8. 日志配置 (Logging)
日志级别设置：
- **LogLevel**:
    - **Default**: `Information` - 默认日志级别为信息
    - **Microsoft.AspNetCore**: `Warning` - ASP.NET Core 相关日志级别为警告

---

## 注意事项
1. **安全性**:
    - 请妥善保存配置文件中的敏感信息（如密码、密钥等），避免泄露。
    - JWT 密钥 (`Secret`) 应足够复杂且定期更换。
2. **环境配置**:
    - 当前配置中的地址（如 `localhost:7028` 和 `localhost:7179`）为本地开发环境，请根据生产环境调整。
3. **数据库与缓存**:
    - 确保 PostgreSQL 和 Redis 服务已正确部署并可访问。
4. **密码策略**:
    - 根据 `IdentityOptions` 配置，用户密码必须满足指定的复杂性要求。

如需进一步调整配置或获取更多信息，请联系项目管理员。

--- 

希望这个 README 文档对您有帮助！如果需要进一步修改或补充，请告诉我。