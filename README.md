# 🚀 TD2 Blacklist System

一个基于 **Flask + MySQL + IP情报分析 + 权限控制** 的综合安全管理系统，集成：

- 🔍 黑名单查询系统
- 📝 玩家封禁记录
- 🚫 IP 黑名单 / 自动封禁
- 🌍 IP 地理位置解析（IPv4 + IPv6）
- 📊 攻击统计分析
- 🧾 实时日志系统
- 👤 多级权限控制系统（含 Root 超级管理员）

---

# 📌 项目核心特点

## 🔥 安全能力
- 自动识别攻击路径（如 `.env / wp-admin / shell`）
- 达到阈值自动封禁 IP
- 支持临时 / 永久封禁
- Cloudflare 真实 IP 识别
- 防止绕过 CDN 直接攻击源站

---

## 🌍 IP 智能解析

采用双引擎融合：

- `ip2region` → 国内高精度解析
- `GeoIP (MaxMind)` → 全球 + ASN + 机房识别

支持：

- IPv4 / IPv6
- ISP / 云厂商识别（AWS / Azure / 阿里云等）
- 住宅 / 机房 IP 判断
- 风险等级评估（高 / 中 / 低）

---

## 🎨 前端系统

### 🔍 黑名单查询页面（search.html）
- UUID / 玩家名 查询
- 卡片式 UI 展示
- 视频证据标识
- 平滑动画效果

---

### 📝 黑名单提交（record.html）
- 添加封禁玩家
- 备注 + 证据链接
- 自动记录时间

---

### 🚫 IP 管理页面（ip_manage.html）
- IP 封禁 / 解封
- 风险等级显示
- 实时日志联动

---

### 👤 用户管理（user_manage.html）
- 用户创建 / 删除
- 权限分配
- 页面访问控制（allowed_pages）

---

### 📊 数据展示（show_existing_data.html）
- 数据库内容可视化
- 历史记录查看

---

# 👤 权限系统（重要）

系统包含四级权限：

| 角色 | 权限 |
|------|------|
| normal | 仅查询 |
| admin | 查询 + 管理 |
| super_admin | 全部权限 |
| **root_super_admin** | ⭐ 最高权限 |

---

## ⭐ Root 超级管理员机制

系统中存在一个**隐藏最高权限角色**：

- Root 本质也是 `super_admin`
- **唯一可以创建其他 super_admin**
- 不通过数据库控制，而是通过配置文件控制

### 配置文件：

```
config/config.json
```

```json
"root_super_admin": ["admin"]
```

### 说明：

- 列表中的账号即为 Root 管理员
- 可设置多个 Root
- Root 权限 > 所有管理员
- 普通 super_admin **无法创建新的 super_admin**

---

## 🔐 权限控制实现

使用装饰器：

```python
@check_login
@check_admin
@check_super_admin
```

控制：

- 页面访问
- API权限
- 操作级权限（封禁 / 解封）

---

# 🗄️ 数据库设计

## 👤 用户表 `sys_users`

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

## 🚫 黑名单表 `td2ban`

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

# 📊 系统功能

## 🚫 IP 黑名单系统
- 自动封禁攻击 IP
- 手动封禁 / 解封
- 到期自动解除
- JSON 持久化存储

---

## 📈 攻击统计
- 按 IP 统计攻击次数
- 风险等级分类：
  - 高风险
  - 中风险
  - 低风险

---

## 🧾 日志系统

示例：

```
2026-01-01 12:00:00 | INFO | [正常访问] | 用户:admin | IP:1.1.1.1 | 位置:中国 北京 | 状态:200 | 详情:GET /
```

支持：

- 实时日志 API
- 安全事件记录
- 日志轮转（5MB）

---

# 📡 API 接口

## 查询 IP
```
POST /api/query_ip
```

## 实时日志
```
GET /api/real_time_log
```

## 攻击统计
```
GET /api/attack_stats
```

## 解封 IP
```
POST /api/unban_ip
```

---

# ⚙️ 项目结构

```
project/
│
├── myhtml.py              # 主程序（核心逻辑）
│
├── templates/             # 前端页面
│   ├── index.html
│   ├── login.html
│   ├── search.html
│   ├── record.html
│   ├── ip_manage.html
│   ├── user_manage.html
│   └── show_existing_data.html
│
├── static/
│   ├── robots.txt
│   ├── TCTD2_Icon_Phoenix_Secondary_Orange.png
│   ├── icons8-tom-clancy-division-2-48.png
│   └── fonts/
│       ├── SmileySans-Oblique.otf
│       ├── SmileySans-Oblique.ttf
│       ├── SmileySans-Oblique.otf.woff2
│       └── SmileySans-Oblique.ttf.woff2
│
├── config/
│   └── config.json
│
├── geoip/
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb
│
├── ip2region_v4.xdb
├── ip2region_v6.xdb
│
├── logs/
│   └── system.log
│
├── ip_blacklist.json
├── attack_stats.json
└── ip_location_cache.json
```

---

# ⚠️ 重要依赖文件

```
ip2region_v4.xdb
ip2region_v6.xdb
```

```
geoip/
├── GeoLite2-ASN.mmdb
├── GeoLite2-City.mmdb
```

---

# 🌍 IP 数据库来源

- 🗄️ ip2region： [GitHub 仓库](https://github.com/lionsoul2014/ip2region)
- 🌐 GeoIP： [官方文档](https://dev.maxmind.com/geoip/docs/databases/#official-client-apis)

---

# 🚀 安装与运行

## 1️⃣ 安装依赖

```bash
pip install flask flask-limiter flask-mysqldb waitress geoip2 requests ip2region
```

---

## 2️⃣ 配置文件

```
config/config.json
```

---

## 3️⃣ 启动服务

```bash
python myhtml.py
```

生产环境：

```bash
waitress-serve --listen=0.0.0.0:5000 myhtml:app
```

---

# 🔧 核心模块

## 🧠 IP解析

```python
get_ip_location(ip)
get_ip_detail(ip)
```

返回：

- 地理位置
- ISP
- 是否机房
- 风险等级

---

## 🚫 自动封禁逻辑

触发条件：

- 攻击路径命中
- 请求异常频率过高
- 登录失败次数过多
- 非法访问行为

---

## ⚡ 缓存系统

- IP 查询缓存
- JSON 原子写入
- 自动同步
- 防止数据损坏

---

# 🔒 安全设计

- ✔ Cloudflare IP识别
- ✔ Session 安全
- ✔ 防暴力破解
- ✔ 自动封禁
- ✔ API权限控制
- ✔ CSRF 防护

---

# ⚠️ 注意事项

- ⚠️ 建议部署在 Cloudflare 后
- ⚠️ 否则可能误封真实用户
- ⚠️ 必须存在 GeoIP 数据库
- ⚠️ 必须存在 ip2region 数据

---

# 🧩 可扩展方向

- 🌍 攻击地图可视化
- 🤖 AI 风险识别
- 📧 邮件告警
- 🧱 WAF 系统扩展
- 📊 数据大屏

---

# 📄 License

MIT License

---

# 🙌 作者

- Albertette
- Version: v1.0
