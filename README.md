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

# 👤 权限系统（重要）

基础权限：search、record

系统包含四级权限：

| 角色 | 权限说明 |
|------|----------|
| normal | 默认无任何页面访问权限；仅可被基础权限 |
| admin | 拥有基础权限；管理权限（受限） |
| super_admin | 拥有基础权限；管理权限 |
| **root_super_admin** | ⭐ 最高权限（可创建 / 提权 super_admin） |

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

## 🎨 前端系统

### 🔍 黑名单查询页面（search.html）
- 提供黑名单数据的统一查询入口
- 支持基于 **UUID / 玩家名称（模糊匹配）** 的检索方式
- 前后端联动，实现实时查询与结果展示
- 采用卡片式 UI 展示查询结果，提升可读性与交互体验

---

#### 🔎 查询方式

##### ➤ UUID 精确查询
- 输入标准 UUID 进行唯一定位
- 后端进行 **UUID 格式校验**
- 命中后返回该玩家所有历史违规记录

---

##### ➤ 玩家名称查询（模糊匹配）
- 支持按玩家名称进行模糊搜索
- 可匹配历史曾使用过的名称
- 返回所有相关记录（可能包含多个 UUID 或多条违规记录）

---

#### 📦 数据展示结构

查询结果以 **卡片（Card）形式** 展示，每条记录独立显示：

展示字段包括：
- 玩家名称（记录时名称，支持历史名称）
- UUID
- 封禁时间（record_time）
- 违规类型（Type）
  - 新八开挂 / 老八开挂 / 演员 / 爷新 / 特殊
- 详细说明（Remark，可选）
- 视频证据（Video，可选）

---

#### 🎬 视频证据展示

- 若存在视频链接：
  - 显示“🎥 证据”标识
  - 可点击跳转查看（新窗口打开）
- 若无证据：
  - 不显示该字段（前端自动隐藏）

---

#### 🎨 前端交互与 UI
- 卡片式布局（多条记录自动排列）
- 支持暗黑风格 UI（统一系统视觉）
- 动态加载数据（AJAX / Fetch）
- 查询结果实时刷新，无需刷新页面
- 平滑过渡动画（提升用户体验）

---

#### ⚙️ 后端交互逻辑
- 前端提交查询请求（UUID / name）
- 后端接口进行参数校验：
  - UUID → 格式校验（合法性判断）
  - name → 字符串安全过滤
- 查询数据库黑名单表：
  - UUID → 精确匹配
  - name → LIKE 模糊查询
- 返回结构化 JSON 数据
- 前端解析并渲染为卡片列表

---

#### 🚫 异常与边界处理
- UUID 格式错误：
  - 后端拒绝查询请求
  - 返回错误提示信息
- 查询结果为空：
  - 显示“未查询到相关记录”
  - 不渲染卡片区域
- 数据字段缺失：
  - Remark / Video 自动判空隐藏
  - 避免页面结构错乱

---

#### 🔒 安全设计
- 所有查询接口需登录后访问（Session 校验）
- 防止恶意查询（基础参数过滤）
- 防止 SQL 注入（参数化查询）
- 前端不暴露敏感字段（如内部ID）

---

#### 🎯 设计目的
- 提供高效、直观的黑名单检索能力
- 支持历史违规记录完整追溯
- 提升审核与管理效率
- 优化用户查询体验（UI + 动效）
- 保证数据展示的准确性与一致性

---

### 📝 黑名单提交（record.html）
- 提供黑名单录入入口，用于登记违规玩家信息
- 表单提交后由后端进行统一校验与处理
- 自动记录封禁时间并写入数据库

---

#### 📥 提交字段说明
- 玩家名称（Name，必填）
- UUID（唯一标识，必填，需符合 UUID 格式）
- 违规类型（Type，必选）
- 详细说明（Remark，可选）
- 视频证据（可选）

---

#### ⚠️ 违规类型（Type）限定值
系统仅允许以下类型：
- 新八开挂
- 老八开挂
- 演员
- 爷新
- 特殊

> 非上述类型将被视为非法数据（由前端或后端校验拦截）

---

#### 🔍 UUID 校验规则
- 必须为非空
- 必须符合标准 UUID 格式（如：`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`）
- 非法格式将被直接拦截，不进入后续逻辑

---

#### ⚙️ 提交流程
1. 用户填写表单并提交
2. 后端接收数据并进行基础校验：
   - UUID 是否为空
   - UUID 格式是否合法
   - Type 是否为合法枚举值
3. 执行 **UUID 唯一性检测**：
   - 若不存在 → 直接写入数据库
   - 若已存在 → 触发重复检测逻辑（跳转 show_existing_data 页面）

---

#### 📌 数据处理逻辑
- 自动生成当前日期（Date）
- 数据写入表：`td2ban`
- 同一 UUID 支持多条记录（不同违规事件）
- Remark 字段允许为空，不影响数据写入

---

#### 🎯 页面特性
- 表单结构清晰，支持快速录入
- 与重复检测页面联动（防止误操作）
- 前端 + 后端双重校验（UUID / Type）
- 提交后具备明确反馈或跳转逻辑

---

#### 🧠 设计目的
- 统一黑名单录入入口
- 保证 UUID 数据合法性
- 规范违规类型（防止脏数据）
- 避免重复 / 冲突数据污染
- 支持玩家违规行为的持续追踪
- 提供可审计的数据记录体系

---

### ⚠️ 重复提交检测（show_existing_data.html）
- 当提交黑名单时，系统会基于 **UUID** 进行唯一性校验
- 若该玩家已存在于数据库（黑名单中），系统将**默认拦截本次提交**
- 自动跳转至该页面展示该玩家的历史封禁记录
- 若确认属于**不同违规事件**，可手动选择继续提交

展示内容包括：
- 玩家当时登记名称（历史名称）
- UUID
- 封禁时间
- 违规类型（Type）
- 详细违规说明（Remark）
- 视频证据（如存在）

作用：
- 防止重复数据写入（去重）
- 支持多次违规记录补充
- 提供完整历史追溯能力
- 提升数据一致性与可靠性

---

### 🚫 IP 管理页面（ip_manage.html）
- 提供系统级 **IP 风险控制与封禁管理入口**
- IP 封禁由系统自动执行（基于攻击行为）
- 管理页面主要用于 **查看风险数据与执行解封操作**
- 用于防御异常访问、攻击行为与滥用请求
- **normal 角色无任何访问/分配权限**

---

#### 📥 数据来源
IP 数据主要来源于：
- 攻击统计模块（`ATTACK_STATS`）
- 系统访问日志分析
- 后端实时记录的异常请求行为

---

#### ⚙️ 核心功能模块

##### ➤ 🤖 自动封禁机制（Auto Ban IP）
- 系统根据攻击行为自动触发封禁
- 基于攻击次数或异常行为阈值判断
- 超过阈值的 IP 自动加入黑名单
- 无需人工干预（防止响应延迟）

---

##### ➤ 👁️ IP 状态查看（Admin 可用）
- Admin 仅可查看：
  - IP 列表
  - 攻击次数（event_count）
  - 风险等级（risk_level）
  - 当前封禁状态
- ❌ 无封禁 / 解封操作权限

---

##### ➤ ✅ IP 解封（Unban IP）
- 从黑名单中移除指定 IP
- 恢复其正常访问权限
- 支持手动立即解封（无需等待到期）
- ⚠️ 权限限制：
  - 仅 `super_admin` 及以上可执行
  - Admin 无权解封

---

##### ➤ 📊 风险等级展示（Risk Level）
- 基于攻击次数自动评估风险等级

| 攻击次数 | 风险等级 |
|----------|----------|
| 0 - 10   | 低风险   |
| 10 - 50  | 中风险   |
| 50+      | 高风险   |

- 前端以颜色或标签形式高亮显示（红 / 橙 / 绿）

---

##### ➤ 📈 攻击统计展示
- 显示每个 IP 的攻击事件次数（event_count）
- 支持按风险等级排序
- 支持实时刷新数据

---

##### ➤ 📜 实时日志联动
- 与系统日志模块联动
- 实时记录异常行为（如：
  - 高频请求
  - 非法参数访问
  - 未授权访问尝试）
- 提供 IP → 行为 → 风险 的关联视图

---

#### ⏳ IP 封禁过期机制（懒解封）
- 支持非永久封禁（`ban_expire`）

##### ⚠️ 核心机制
- ❌ 不会自动定时解封
- ✅ 仅在 IP 再次访问时触发解封判断

##### 🔄 解封逻辑
- 若未到期 → 拦截
- 若已到期 → 自动解封并放行请求

---

#### 🔄 数据刷新机制
- 页面加载时自动获取最新 IP 数据
- 支持手动刷新
- 后端定时更新攻击统计（不负责解封）

---

#### 🔒 权限控制
| 操作 | admin | super_admin | root |
|------|--------|-------|-------------|------|
| 查看 IP 管理页面 | ✅ 可查看 | ✅ 可查看 | ✅ 可查看 |
| 自动封禁（系统） | ⚙️ 系统执行 | ⚙️ 系统执行 | ⚙️ 系统执行 |
| 手动解封 IP | ❌ 无权限 | ✅ 可执行 | ✅ 可执行 |

---

#### 🧠 安全设计
- 自动封禁机制（减少人工干预）
- 惰性解封（Lazy Unban，降低系统开销）
- IP 级访问拦截（请求入口控制）
- 防止恶意刷接口 / 暴力请求
- 日志联动形成完整攻击链

---

#### 🎯 设计目的
- 实现自动化攻击防御（Auto Defense）
- 降低人工干预成本
- 提供可视化风险分析能力
- 通过高权限控制解封，防止风控绕过
- 提升系统整体安全性与稳定性

---

### 👤 用户管理（user_manage.html）
- 提供系统用户的统一管理入口
- 支持用户创建、权限分配、封禁控制等操作
- 所有操作受权限系统严格限制
- **normal 角色无任何访问/分配权限**

---

#### 📥 用户信息结构
用户数据基于表：`sys_users`

字段说明：
- account（账号，唯一）
- password（加密存储，hash）
- role（角色：normal / admin / super_admin）
- allowed_pages（允许访问的页面列表）
- ban_status（封禁状态：0=正常 / 1=封禁）
- ban_expire（封禁到期时间）
- ban_reason（封禁原因）
- ban_by（操作人，用于权限校验）

---

#### ⚙️ 功能模块

##### ➤ 👤 用户创建
- 创建新账号
- 设置初始角色（normal / admin / super_admin）
- 自动进行密码加密存储
- 校验账号唯一性（防止重复）
- ⚠️ 仅 Root 可创建或提升为 `super_admin`

---

##### ➤ 🗑️ 用户删除
- 删除指定用户账号
- 不可删除自身账号（防止误操作）
- 不允许删除高于或等于自身权限的用户

---

##### ➤ 🔐 权限分配
- 修改用户角色：normal → admin → super_admin
- 动态更新权限，无需重启服务
- ⚠️ `super_admin` 的创建 / 提升仅限 Root 操作
- ⚠️ normal 仅允许分配 search、record 页面，**禁止分配 ip_manage、user_manage**

---

##### ➤ 📄 页面访问控制（allowed_pages）
- 控制用户可访问的前端页面
- 精细化权限管理
- normal 仅允许：
```
["search", "record"]
```
- 未授权页面访问将被后端拦截

--

##### Root 权限特性：
- 唯一可以创建 / 提升 `super_admin`
- 可管理所有用户（admin / normal）
- **不直接管理其他 super_admin（除自身外）**
- 不受普通权限限制
- 拥有系统最高控制权

---

##### ⚠️ 权限限制规则
- 普通 `super_admin` **无法创建新的 super_admin**
- 非 Root 用户无法修改 Root 用户权限
- 不允许越权操作
- normal 禁止分配/访问 ip_manage、user_manage
- 所有敏感操作需通过权限校验装饰器

---

##### ➤ 🚫 用户封禁系统
- 手动封禁用户账号
- 设置封禁时长（ban_expire）
- 自动到期解封
- 封禁期间禁止登录或访问系统
- 所有封禁操作记录操作人（ban_by）

---

##### 🚫 封禁与解封规则（核心逻辑）

###### 👤 Admin 行为限制
- Admin 仅可封禁 `normal` 用户
- **Admin 封禁的用户，仅允许该 Admin 自己解封**
- 其他 Admin **无权解封该用户**

---

###### ⭐ Super Admin / Root 权限
- `super_admin` 与 `root_super_admin`：
  - 可封禁任意 `normal` 用户
  - 可解封**所有用户**（包括由其他 Admin 封禁的用户）

---

###### 🔒 权限总结
| 操作 | admin | super_admin | root |
|------|-------|-------------|------|
| 封禁 normal | ✅ | ✅ | ✅ |
| 解封自己封禁的用户 | ✅ | ✅ | ✅ |
| 解封其他 admin 封禁的用户 | ❌ | ✅ | ✅ |
| 创建 admin | ❌ | ✅ | ✅ |
| 管理 admin | ❌ | ✅ | ✅ |
| 创建 super_admin | ❌ | ❌ | ✅ |
| 管理 super_admin | ❌ | ❌ | ✅ （受限）|

---

#### 🧠 安全设计
- 密码使用哈希存储（Werkzeug）
- Session 登录态校验
- 操作级权限验证（接口层）
- 基于 `ban_by` 的操作绑定控制
- 防止权限横向越权（Admin 之间隔离）
- 高权限兜底机制（super_admin / root 可接管）

---

#### 🎯 设计目的
- 提供统一用户管理入口
- 实现多级权限控制体系
- 支持精细化页面访问控制
- 防止权限滥用与越权操作
- 保证系统整体安全性与可控性

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
- 自动封禁攻击 IP（基于攻击行为与阈值触发）
- 不提供手动封禁（由系统统一控制）
- 支持手动解封（仅 super_admin 及以上权限）
- ❗ 非永久封禁采用惰性解封（Lazy Unban）机制：
  - 不会定时自动解封
  - 仅在 IP 再次访问时触发解封判断
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
