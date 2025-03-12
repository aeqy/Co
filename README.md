# Co
Clean Architecture

# Co 项目 Docker 部署指南

## 目录
1. [项目概述](#项目概述)
2. [环境要求](#环境要求)
3. [快速开始](#快速开始)
4. [配置说明](#配置说明)
5. [常见问题](#常见问题)
6. [生产环境部署](#生产环境部署)
7. [安全建议](#安全建议)
8. [维护与监控](#维护与监控)

---

## 项目概述
本项目基于 Docker 和 Docker Compose 部署，包含以下服务：
- **co.webapi**：基于 ASP.NET Core 的 Web API 服务
- **postgres**：PostgreSQL 数据库服务
- **redis**：Redis 缓存服务

---

## 环境要求
- **Docker**：20.10.0 或更高版本
- **Docker Compose**：1.29.0 或更高版本
- **操作系统**：Linux / macOS / Windows (WSL2)

---

## 快速开始

### 1. 克隆项目

```bash

git clone https://github.com/your-repo/Co.git
cd Co

```

### 2. 配置环境变量
创建 `.env` 文件并填写以下内容：

```bash

DB_PASSWORD=your_db_password
REDIS_PASSWORD=your_redis_password
CERT_PASSWORD=your_cert_password

```

### 3. 启动服务

```bash

docker-compose up -d --build

```

### 4. 验证服务
```bash

curl http://localhost:5000/health

```

---

## 配置说明

### 1. 网络配置
- **co-network**：默认桥接网络，用于服务间通信
- **端口映射**：Web API 服务默认映射到宿主机 5000 端口

### 2. 环境变量
| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `DB_PASSWORD` | PostgreSQL 数据库密码 | 必填 |
| `REDIS_PASSWORD` | Redis 密码 | 必填 |
| `CERT_PASSWORD` | HTTPS 证书密码 | 必填 |

### 3. 数据持久化
- **PostgreSQL**：数据存储在 `pgdata` 卷中
- **Redis**：配置文件挂载到 `./redis/redis.conf`

---

## 常见问题

### 1. 端口冲突
**现象**：`Bind for 0.0.0.0:5000 failed: port is already allocated`  
**解决方案**：
- 更换端口：
  ```yaml
  
  ports:
    - published: 5001  # 改为未占用的端口
      target: 80
      protocol: tcp
  
  ```
- 清理残留容器：
  ```bash
  
  docker-compose down --volumes
  
  ```

### 2. 网络配置错误
**现象**：`network co_co-network was found but has incorrect label`  
**解决方案**：
- 清理网络：

  ```bash
  
  docker network rm co_co-network
  docker network prune -f
  
  ```
- 重新部署：
  ```bash
  
  docker-compose up -d
  
  ```

### 3. 证书加载失败
**现象**：`Could not open file or uri for loading private key`  
**解决方案**：
- 确保证书文件存在：
  ```bash
  
  ls -l certs/
  
  ```
- 重新生成证书：
  ```bash
  
  ./generate-certs.sh
  
  ```

---

## 生产环境部署

### 1. 启用 HTTPS
```yaml
services:
  co.webapi:
    environment:
      ASPNETCORE_URLS: "https://+:443;http://+:80"
      ASPNETCORE_Kestrel__Certificates__Default__Password: ${CERT_PASSWORD}
      ASPNETCORE_Kestrel__Certificates__Default__Path: /https/co.pfx
    volumes:
      - ./certs/co.pfx:/https/co.pfx:ro
    ports:
      - "5000:443"

```

### 2. 使用 Nginx 反向代理
```nginx

server {
    listen 443 ssl;
    server_name co.example.com;

    ssl_certificate /etc/ssl/certs/co.crt;
    ssl_certificate_key /etc/ssl/certs/co.key;

    location / {
        proxy_pass https://co.webapi:443;
    }
}

```

### 3. 多节点部署
```yaml

deploy:
  replicas: 3
  endpoint_mode: vip
  placement:
    constraints:
      - node.role == manager
```

---

## 安全建议

### 1. 密码管理
- 使用 Docker Secrets 管理敏感信息：
  ```bash
  
  echo "${DB_PASSWORD}" | docker secret create db_password -
  
  ```

### 2. 网络隔离
```yaml

networks:
  co-network:
    internal: true  # 禁止外部直接访问
    attachable: false

```

### 3. 容器安全
```yaml

services:
  co.webapi:
    security_opt:
      - no-new-privileges
    read_only: true
    tmpfs:
      - /app/tmp:rw,size=100M

```

---

## 维护与监控

### 1. 日志管理
```bash

# 查看实时日志
docker-compose logs -f co.webapi

# 导出日志文件
docker-compose logs co.webapi > webapi.log

```

### 2. 健康检查
```yaml

healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:80/health"]
  interval: 30s
  timeout: 10s
  retries: 3

```

### 3. 备份与恢复
```bash

# PostgreSQL 备份
docker exec postgres pg_dump -U prod_user co_db > backup.sql

# Redis 持久化
cp -r volumes/redis/dump.rdb ./backup/

```

---

## 附录

### 1. 常用命令
| 命令 | 说明 |
|------|------|
| `docker-compose up -d` | 启动服务 |
| `docker-compose down` | 停止服务 |
| `docker-compose logs` | 查看日志 |
| `docker-compose exec postgres psql` | 进入 PostgreSQL |

### 2. 参考文档
- [Docker 官方文档](https://docs.docker.com/)
- [ASP.NET Core 容器化指南](https://docs.microsoft.com/aspnet/core/host-and-deploy/docker)

---

通过以上配置和指南，您可以快速部署和管理 Co 项目。如有问题，请参考 [常见问题](#常见问题) 或[提交 Issue](https://github.com/aeqy/Co.git)。