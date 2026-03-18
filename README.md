# 📌 TD2 Blacklist System

一个基于 **Flask + MySQL + IP情报分析** 的安全管理系统，集成：

- 🔐 登录认证 & 权限控制
- 🚫 IP 黑名单系统
- 🌍 IP 地理位置解析（IPv4 + IPv6）
- ⚡ 实时攻击检测 & 自动封禁
- 📊 攻击统计分析
- 🧠 智能 IP 类型识别（住宅 / VPS / 云 / CDN）
- 📝 日志系统（带地理位置）

---

# 📷 项目特点

## 🔥 安全能力
- 自动识别攻击路径（如 `.env / wp-admin / shell`）
- 超过阈值自动封禁 IP
- 支持永久 / 临时封禁
- Cloudflare 真实 IP 识别
- 防止直接 IP 访问攻击

---

## 🌍 IP 解析（核心亮点）

采用混合引擎：

- `ip2region`（国内精准）
- `GeoLite2`（国外 + ASN）

支持：

- IPv4 / IPv6 双栈
- ISP 识别（电信 / 联通 / AWS / Azure 等）
- 数据中心检测（机房 IP）
- 风险评级（高危 / 中风险 / 低风险）

---

# 📊 系统功能

## 👤 用户系统
- 登录 / 登出
- 角色：
  - `normal`
  - `admin`
  - `super_admin`
- 页面权限控制
- 用户封禁系统

---

## 🚫 IP 黑名单
- 自动封禁攻击 IP
- 手动封禁 / 解封
- 过期自动解除
- 黑名单持久化（JSON）

---

## 📈 攻击统计
- 按 IP 统计攻击次数
- 风险等级：
  - 高风险
  - 中风险
  - 低风险

---

## 🧾 日志系统

日志格式示例：

```
2026-01-01 12:00:00 | INFO | [正常访问] | 用户:admin | IP:1.1.1.1 | 位置:中国 北京 | 状态:200 | 详情:GET /
```

支持：

- 实时日志 API
- 自动记录安全事件
- 文件轮转（5MB）

---

# ⚠️ 重要运行依赖（必须存在）

## 📂 主目录

```
ip2region_v4.xdb
ip2region_v6.xdb
```

---

## 📂 GeoIP 数据库

```
geoip/
├── GeoLite2-ASN.mmdb
├── GeoLite2-City.mmdb
```

> ❗ 缺失将导致 IP 解析功能异常

---

# ⚙️ 项目结构

```
project/
│
├── myhtml.py
│
├── ip2region_v4.xdb
├── ip2region_v6.xdb
│
├── geoip/
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb
│
├── config/
│   └── config.json
│
├── templates/
├── static/
│
├── logs/
│   └── system.log
│
├── ip_blacklist.json
├── attack_stats.json
├── ip_location_cache.json
```

---

# 🚀 安装与运行

## 1️⃣ 安装依赖

```bash
pip install flask flask-limiter flask-mysqldb waitress geoip2 requests ip2region
```

---

## 2️⃣ 配置文件

路径：

```
config/config.json
```

示例：

```json
{
  "flask": {
    "secret_key": "your_secret_key"
  },
  "mysql": {
    "host": "127.0.0.1",
    "user": "root",
    "password": "123456",
    "database": "td2",
    "port": 3306
  },
  "security": {
    "ban_duration": 86400
  },
  "geoip": {
    "account_id": "",
    "license_key": ""
  },
  "root_super_admin": ["admin"]
}
```

---

## 3️⃣ 初始化数据库

### 表：`sys_users`

```sql
CREATE TABLE sys_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  account VARCHAR(50) UNIQUE,
  password TEXT,
  role VARCHAR(20),
  allowed_pages TEXT,
  ban_status INT DEFAULT 0,
  ban_expire BIGINT DEFAULT 0,
  ban_reason TEXT,
  ban_by VARCHAR(50)
);
```

---

### 表：`td2ban`

```sql
CREATE TABLE td2ban (
  Name VARCHAR(50),
  Uuid VARCHAR(50),
  Type VARCHAR(50),
  Remark TEXT,
  Date DATE
);
```

---

## 4️⃣ 启动服务

```bash
python myhtml.py
```

生产环境：

```bash
waitress-serve --listen=0.0.0.0:5000 myhtml:app
```

---

# 🔧 核心模块说明

## 🧠 IP解析

```python
get_ip_location(ip)
get_ip_detail(ip)
```

返回：

- 国家 / 省 / 城市
- ISP
- 是否机房
- 风险等级

---

## 🚫 封禁机制

触发条件：

- 攻击路径命中
- 安全事件 ≥ 30
- 登录失败过多
- 直接 IP 访问

---

## ⚡ 缓存系统

- 自动缓存 IP 查询结果
- 原子写入（防止损坏）
- 启动时全量同步
- 文件变更自动更新

---

# 🔒 安全设计

- ✔ Cloudflare IP 识别
- ✔ Session 安全 Cookie
- ✔ 防暴力破解
- ✔ 自动封禁策略
- ✔ API 权限控制
- ✔ CSRF Token（表单提交）

---

# 📡 API接口

## 查询 IP

```
POST /api/query_ip
```

---

## 实时日志

```
GET /api/real_time_log
```

---

## 攻击统计

```
GET /api/attack_stats
```

---

## 解封 IP

```
POST /api/unban_ip
```

---

# ⚠️ 注意事项

- ⚠️ 必须部署在 Cloudflare 后面
- ⚠️ 否则可能触发安全策略误封
- ⚠️ 必须存在 GeoIP 数据库
- ⚠️ 必须存在 ip2region 数据文件

---

# 🧩 后续可扩展

- 🔍 地图可视化攻击来源
- 🤖 AI 风险分析
- 📧 邮件告警系统
- 🧱 WAF 规则扩展
- 📊 数据大屏

---

# 📄 License

MIT License

---

# 🙌 作者

- Author: Albertette
- Version: v1.0
