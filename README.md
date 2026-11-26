# ezstore

**自用的简易密钥存储服务**：把散落的 API Key、账号密码统一存在一处，加密落库、按 agent 分权、每次读写都留痕，并提供 CLI、HTTP API 和 MCP 三种入口。

> 定位说明：这是一个**给自己和小团队用**的轻量工具，不是企业级密钥管理平台。它刻意保持单二进制、零外部依赖、代码可通读，方便随时改、随时审计。

## 它解决什么问题

AI agent 需要密钥才能干活，但直接写进环境变量或配置文件有几个麻烦：

- 密钥散落在十几个项目里，轮换时找不到全部位置
- 某个 agent 本来只该读 `team/a/` 下的东西，却能看见全部
- 谁在什么时候读走了哪一个密钥，事后查不到
- 改错了值想退回上一版，没有历史

ezstore 就是把这些收拢：**一份加密存储 + 按前缀分权 + 版本历史 + 可校验的审计日志**，agent 通过 MCP 取用，人和脚本通过 CLI / HTTP 取用。

## 功能

### 密钥存取

- 名字用斜杠分层（`team/stripe/prod-key`），天然适合按项目、环境归类
- 支持标签（`env=prod`、`owner=alice`），列表时可按键或键值过滤
- 单个值上限 60 KB，空值拒绝
- 名称有严格校验：不接受空格、通配符、`..`、连续斜杠，避免和权限规则混淆

### 版本历史

- **每次写入都产生新版本，旧版本永不覆盖**
- 可以按版本号读取任意历史值：`ezstore secret get team/key --version 3`
- **回滚本身也是一个新版本**，所以回滚可以再回滚，历史永远可追溯
- 版本列表会显示时间、写入者、明文 SHA-256 校验和（不暴露值）
- 可配置保留数量（`retain_versions`），0 表示全留

### 多 Agent 分权

每个 token 绑定两部分授权：

| 维度 | 说明 | 示例 |
|---|---|---|
| scope | 能碰哪些名字，支持通配符 | `team/a/**`、`shared/*` |
| perms | 能做什么 | `read`、`write`、`delete`、`admin` |

- scope 语法：`*` 匹配一段，`**` 匹配零到多段
- 越权在服务层被拒绝，**并且这次拒绝会写进审计**
- 列表操作只返回当前 token 可见的名字，不会泄露其他前缀的存在
- token 支持过期时间，明文只在签发时显示一次，库里只存 SHA-256 哈希
- 每个 agent 一个 token，互不干扰

### 审计日志

- 每次读取、写入、删除、回滚、列表都记录：时间、操作者、动作、目标、结果
- **哈希链**：每条记录带前一条的哈希，篡改任意一行会让其后所有记录校验失败
- `ezstore audit verify` 一条命令校验整条链
- **日志里没有 value 字段**，因为不该有

### 加密与主密钥

- 值用 AES-256-GCM 加密后入库，**数据库里永远是密文**
- 每条密文绑定「名字 + 版本号」，把密文挪到别的行会解密失败，而不是静默解出错误的值
- Windows 上主密钥用 DPAPI 封装，只有创建它的 Windows 账户能解开
- Linux / macOS 用 0600 权限文件 + 权限位校验
- 也支持 `EZSTORE_MASTER_KEY` 环境变量（容器场景，属于最弱模式）

### 双数据库

- 默认 SQLite，**零配置，一个文件就是整个库**
- 需要多人/多实例时切 MySQL，改 `database.driver` 一行即可
- 两边的行为刻意对齐，包括时间精度对审计链的影响

### 三种入口

| 入口 | 给谁用 | 说明 |
|---|---|---|
| CLI | 人 | 12 个子命令，直接操作数据库，不需要 HTTP 服务在跑 |
| HTTP API | 脚本 / 其他服务 | Gin 提供，Bearer token 认证，RESTful 风格 |
| MCP | AI agent | stdio 传输，6 个工具，接进 DSH / Claude / Cursor 即可 |

三个入口走**同一套业务逻辑**，权限规则不会因为入口不同而出现差异。

## 快速开始

```bash
go build -trimpath -ldflags "-s -w" -o bin/ezstore ./cmd/ezstore
```

```bash
mkdir ezstore-data && cd ezstore-data
../bin/ezstore init --admin-token
# 记下打印出来的 admin token（只显示一次）

# 给 agent 发一个只能读写 team/ 下的 token
../bin/ezstore token create --name agent-a --scopes "team/**" --perms read,write

# 存密钥：值从隐藏提示或管道读入，不接受命令行参数
echo "sk_live_xxx" | ../bin/ezstore secret set team/stripe/prod-key --tag env=prod --stdin

# 读、列、看历史
../bin/ezstore secret get team/stripe/prod-key
../bin/ezstore secret ls
../bin/ezstore secret history team/stripe/prod-key

# 审计
../bin/ezstore audit tail
../bin/ezstore audit verify
```

## 命令一览

| 命令 | 作用 |
|---|---|
| `ezstore init [--admin-token] [--driver sqlite\|mysql] [--dsn DSN]` | 创建配置、主密钥、数据库表 |
| `ezstore serve [--addr 127.0.0.1:8787]` | 启动 HTTP API |
| `ezstore mcp` | 启动 MCP stdio 服务（需要 `EZSTORE_TOKEN`） |
| `ezstore secret set <名字> [--tag k=v] [--stdin]` | 写入新版本 |
| `ezstore secret get <名字> [--version N]` | 输出明文 |
| `ezstore secret ls [--prefix p] [--tag k=v] [--limit N]` | 列名字和元数据，不含值 |
| `ezstore secret rm <名字> [--purge --yes]` | 软删除；`--purge` 连历史一起删 |
| `ezstore secret history <名字>` | 版本列表 |
| `ezstore secret rollback <名字> --version N` | 把旧版本复制成新版本 |
| `ezstore token create --name N --scopes GLOB[,GLOB] [--perms ...] [--ttl 720h]` | 签发 token |
| `ezstore token ls` / `ezstore token rm --name N` | 列出 / 吊销 |
| `ezstore audit tail [--limit N]` / `ezstore audit verify` | 查看 / 校验审计链 |
| `ezstore doctor` | 自检配置、主密钥、数据库、审计链 |

配置文件用 `-c` 指定：`ezstore -c /etc/ezstore/ezstore.toml secret ls`

## 配置

`ezstore.toml`（`init` 自动生成）：

```toml
[server]
addr = "127.0.0.1:8787"

[database]
# sqlite: 文件路径；mysql: user:pass@tcp(host:3306)/ezstore
driver = "sqlite"
dsn = "ezstore.db"

[security]
master_key_file = "master.key"
# 0 = 保留全部版本；N = 只保留最新 N 个
retain_versions = 0
```

## HTTP API

除 `/healthz` 外都需要 `Authorization: Bearer ezs_...`。

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/healthz` | 健康检查 |
| POST | `/v1/secrets` | 写入 `{name, value, tags}` |
| GET | `/v1/secrets/get?name=&version=` | 读取明文 |
| GET | `/v1/secrets?prefix=&tag=&limit=` | 列表，不含值 |
| DELETE | `/v1/secrets?name=&purge=` | 删除 |
| GET | `/v1/secrets/versions?name=&limit=` | 版本列表 |
| POST | `/v1/secrets/rollback` | 回滚 `{name, version}` |
| POST / GET / DELETE | `/v1/tokens` | 签发 / 列出 / 吊销（需 admin） |
| GET | `/v1/audit?limit=` | 审计尾部（需 admin） |
| GET | `/v1/audit/verify` | 校验哈希链（需 admin） |

错误统一格式：

```json
{ "error": { "code": "permission_denied", "message": "permission denied: read on \"other/x\"" } }
```

## MCP

六个工具，返回 JSON 文本块：

| 工具 | 参数 | 作用 |
|---|---|---|
| `secret_get` | `name`, `version?` | 读取密钥 |
| `secret_put` | `name`, `value`, `tags?` | 写入新版本 |
| `secret_list` | `prefix?`, `tag?`, `limit?` | 列名字，不含值 |
| `secret_delete` | `name`, `purge?` | 删除 |
| `secret_history` | `name`, `limit?` | 版本列表 |
| `secret_rollback` | `name`, `version` | 回滚 |

越权这类业务错误以 `isError: true` 的工具结果返回（模型能看到原因），只有协议层错误才用 JSON-RPC error。

### 接入 DeepSeek Harness

```json
{
  "type": "stdio",
  "name": "ezstore",
  "command": "D:\\Projects\\ezstore\\bin\\ezstore.exe",
  "args": ["-c", "D:\\Projects\\ezstore\\ezstore.toml", "mcp"],
  "env": [{ "name": "EZSTORE_TOKEN", "value": "ezs_这里填agent的token" }]
}
```

`command` 必须是绝对路径。每个 agent 用独立 token、独立 scope，这样即使某个 agent 被诱导越权，也只是拿到一个 `permission denied`，而且这条记录会进审计。

## 安全边界

**能做到**

- 数据库里只有密文，明文只存在于服务进程内存和响应里
- 密文绑定名字和版本，行被搬到别处会解密失败
- token 只存哈希，明文只显示一次
- 审计不含值，哈希链可离线校验
- 不同 token 之间互相看不见对方的密钥

**做不到（请务必知道）**

- **不防同机同账户的其他进程**：它们能读配置、能读 `master.key`，也能直接 `ezstore secret get`
- **不防拿到 token 的 agent 读取其 scope 内的一切**：scope 是前缀级，不是逐条级
- **不防能力滥用**：有 `write` 权限的 agent 可以覆盖别人的密钥（历史还在，可回滚）
- 数据库整库被拷走时，安全性只剩主密钥强度
- 没有主密钥轮换：换主密钥需要重新加密全部历史

要形成真正的边界，得让 ezstore 和 agent 跑在不同系统账户下。单机同账户时，它是**分权和审计工具**，不是**对抗本机恶意代码的墙**。

主密钥模式对比：

| 模式 | 强度 | 适用 |
|---|---|---|
| Windows DPAPI（默认） | 中高，绑定 Windows 账户 | 单机 |
| 文件 0600 | 中，依赖文件权限 | 服务器 |
| `EZSTORE_MASTER_KEY` 环境变量 | 低，进程环境可见 | 容器 / CI |

备份时把 `master.key` 和数据库**分开**保管；主密钥丢了，历史密文全部解不开。

## 技术栈

Go 1.27 · Gin（HTTP）· GORM + SQLite/MySQL · TOML 配置 · JSON-RPC 2.0（MCP 手写实现）· AES-256-GCM / DPAPI。

分层清晰（`domain ← repository ← service ← transport`），domain 层不依赖任何框架，方便替换或测试。

## 项目状态

个人自用项目，功能可用、测试覆盖主要路径（`go test ./...` 全绿）。

已知限制：

- 无 Web UI，管理走 CLI
- 无密钥轮换命令
- 审计表不做归档，长期运行需自行轮转
- MySQL 链路未做实机并发验证（SQLite 已充分测试）

欢迎提 issue，但请按「自用工具」的预期来评估它的成熟度。

## 许可

MIT
