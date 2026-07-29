# CLAUDE.md

## 会话启动必做

- 每次会话开始时，先执行一次 `pwd` 确认当前工作目录。本项目经常在 git worktree（如 `~/.superset/worktrees/...`）中工作，**所有绝对路径必须基于 `pwd` 的结果来拼**，不要根据提示词中出现的主仓库路径去猜测文件位置。

## 经 tool-bridge 用数据库与日志（优先于直连 MCP）

生产网关 `https://tool-bridge.fantacy.live`，本机已有 profile（`~/.config/tool-bridge/config.json`，current=`fantacy`）。
CLI 未全局安装，在本仓库内用 `npx tsx packages/cli/src/index.ts <...>`（下文简写 `tb`）。

**为什么走 tool-bridge 而不是直接挂 MCP**：会话内的 bytebase MCP 连接是 OAuth，token 1h 过期后要人工 `/mcp` 重新登录；
tool-bridge 的 plugin 用服务账号自动换发令牌，永不过期、零人工授权。日志同理（凭证由平台注入）。

### 节点一览

| 节点 | 用途 | 权限 |
|---|---|---|
| `plugins/bytebase` | Bytebase 数据库（查询 / 看 schema） | **纯只读** |
| `plugins/bytebase-rw` | Bytebase 数据库（改动） | test 可直接写；**生产只能提工单** |
| `mcp/tipsy` | 阿里云 SLS 日志查询（经 MetaMCP 聚合） | 读 |

### 用法

```sh
tb help plugins/bytebase          # 工具列表 + Notes 段里有数据库定位速查表
tb call plugins/bytebase/query_database '{"database":"fantasy","instance":"tipsy-backend-test-mysql-v8kd","statement":"SELECT 1"}'
tb call plugins/bytebase/get_schema   '{"database":"tipsy_chat","instance":"tipsy-studio"}'
tb call mcp/tipsy/aluiyun-sls-mcp__sls_list_projects '{"regionId":"cn-hangzhou"}'
```

**查询数据库前先 `tb help plugins/bytebase` 读 Notes**——那里有实测过的「用途 → 环境 → instance → database」映射表，
不要凭库名猜实例。三个必踩的坑：

1. **`instance` 必须传**。库名跨实例重名（`studio` 在 prod 有两个、`new-api`/`newapi` 三处、`tipsy_memory` 在 test 有两个），
   只传 `database` 会 `AMBIGUOUS_TARGET` 或落错环境。
2. **test/prod 命名不对称，别按 test 名猜 prod**：`tipsy_chat`→`studio`、`tipsy-ab-config`→`ab-config`、`tipsy_memory`→`memory`。
3. **实例名与项目名对不上**：memory 的 prod 库在 `studiorprod` 上，new-api 的 test 库在 `tipsy-studio` 上。

常用几个（完整表见节点 Notes）：tipsy 后端 test=`tipsy-backend-test-mysql-v8kd/fantasy`、prod=`tipsy-backend-prod-mysql-sj6z/tipsy`；
studio 主库 test=`tipsy-studio/tipsy_chat`、prod=`studiorprod/studio`。

### 改动数据库

- **test 环境**：`tb call plugins/bytebase-rw/query_database` 直接跑 DDL/DML。
- **生产环境**：只能 `plugins/bytebase-rw/propose_database_change`（database+instance+sql+title）提工单；
  直写会被拒（`permission denied to access resources`）。工单默认不创建 rollout，需人工在 Bytebase UI 审批执行。
- 只读查询走 `plugins/bytebase`（最小权限），`-rw` 留给确实要改动的场合。
- 在生产库上做验证性写入前先问我；test 库建的临时表用完即删。
