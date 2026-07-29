# @tool-bridge/plugin-bytebase

Bytebase 自托管 MCP 的 tool-provider/v1 plugin(Cloudflare Worker)。

**为什么要它**:Bytebase 的 `/mcp` 只认 OAuth bearer,而它的动态客户端注册(DCR)白名单只放行
loopback 回调 —— 直挂 `kind:mcp` 每次授权都得在本机开浏览器(`tb tool auth --local`),拿到的
access token 只活 1h,refresh token 轮换在多 isolate 并发下还会互相作废。

本 plugin 改走 Bytebase **服务账号(Service Account)**:用 service key 按需换发访问令牌并缓存到
快过期前,上游 401 时强制重换发重试一次。对平台侧就是一个永不过期、零人工授权的工具源 ——
本机与任何客户端只面对 tool-bridge 的长期 SK。

## 前置:建服务账号并授最小权限

1. Bytebase 控制台 **IAM & Admin → Service Accounts → Add Service Account**(或项目级
   **Project → Manage → Service Accounts**,更符合最小权限)。
2. 记下邮箱(形如 `<name>@service.bytebase.com`)与**创建时一次性返回的 service key**(`bbs_` 前缀)。
3. 给它授角色。**这是第一道也是最硬的权限闸**:SA 继承自己的 IAM 角色,审计日志记在 SA 名下而不是
   真实调用者。只读用途只给 `sqlEditorReadUser` / `projectViewer` 之类;要允许提改动才给写角色。

也可以用 API 建(需已有管理员凭证):

```sh
# ListWorkspaces 拿 workspace id;parent 也可以是 projects/{project}
curl -sX POST "$BB_URL/v1/workspaces/{ws}/serviceAccounts?serviceAccountId=tool-bridge" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"title":"tool-bridge plugin"}'
```

## 部署与注册

```sh
# 1. 改 wrangler.jsonc:account_id、BYTEBASE_BASE_URL(也可留给凭证里的 base_url)
pnpm --filter @tool-bridge/plugin-bytebase deploy

# 2. 平台注册(拿到 pluginToken),再把它配进 Worker secret
tb plugin register --id bytebase --endpoint https://tb-plugin-bytebase.<subdomain>.workers.dev --auth platform-token
pnpm --filter @tool-bridge/plugin-bytebase exec wrangler secret put PLUGIN_TOKEN

# 3. 凭证存平台(不落 plugin),再挂载并引用它
tb secret set --name bytebase-sa   # 值:{"email":"...@service.bytebase.com","service_key":"bbs_...","base_url":"https://bytebase.example.com"}
tb tool mount bytebase --plugin bytebase --auth-ref bytebase-sa

# 4. 验证
tb help bytebase
```

`base_url` 在凭证 JSON 里给时优先于 `BYTEBASE_BASE_URL`,同一份部署可以服务多个实例/多个账号的
挂载(令牌与 MCP 会话缓存按 `<baseUrl>|<email>` 键控,互不串号)。

## env

| 名 | 类型 | 说明 |
|---|---|---|
| `PLUGIN_TOKEN` | secret | 平台签发的 pluginToken。注册前可暂缺(此时仅要求 Bearer 非空) |
| `BYTEBASE_BASE_URL` | vars | 实例 base URL;凭证内 `base_url` 优先。二者皆缺 → 调用报 unavailable |
| `BYTEBASE_ALLOWED_TOOLS` | vars | 工具白名单(逗号分隔)。留空 = 放行上游全部工具。填了则 List 过滤 **且** Call 拒绝 |

Bytebase 凭证**不配在这里** —— 存平台 SecretStore,由挂载的 `authRef` 经 `X-TB-Upstream-Auth`
每次调用注入。plugin 无凭证即空壳:endpoint 公网可达、PLUGIN_TOKEN 万一泄漏,也拿不到任何
Bytebase 凭证;轮换 service key 只需 `tb secret set`,不必重新部署。

## 上游已知行为(3.19.0 实测)

- `tools/list` 宣告 6 个工具,且**不带 annotations** → plugin 按工具名兜底 `effect`
  (`propose_database_change` → destructive、`query_database`/`get_schema`/`search_api`/`get_skill` → read、
  `call_api` → write)。上游哪天补了 annotations,以 annotations 为准。
- 失效信号分两层:坏/过期 token → **401**(强制重换发令牌);有效 token + 陈旧 sessionId → **404**
  (清会话完整重握手)。两者不可混淆。
- 换发响应只有 `token`,**没有 expires_in** —— 到期时刻解 JWT `exp`(实测固定 1h)。
- login 有按 email 的失败锁定:service key 配错时换发失败**不重试**,以免锁号。
- 令牌与会话缓存键含 `sha256(service_key)` 前 16 hex。只按 `baseUrl|email` 键控时,错 key 会命中
  同 email 的有效缓存并返回 200 —— 那既破坏"plugin 无凭证即空壳",也让 key 轮换延迟到旧令牌到期。

## 当前生产部署(2026-07-29)

Worker `tb-plugin-bytebase` @ https://tb-plugin-bytebase.heco.workers.dev(Lightspeed 账户),
上游 https://bytebase.infra.fantacy.live(Bytebase 3.19.0),网关注册 id=`bytebase`,白名单留空(放行全部 6 工具)。

**一份部署,两个挂载做权限分级**(令牌缓存按 key 摘要隔离,互不串号):

| 挂载路径 | authRef / SA | 能做什么 |
|---|---|---|
| `bytebase` | `bytebase-sa` / `tool-bridge@` | 纯只读(`roles/sqlEditorReadUser`)。日常查询与看 schema 用这个 |
| `bytebase-rw` | `bytebase-rw` / `tool-bridge-rw@` | **test 环境直接写** + **全环境提工单**;生产库只能提单不能直写 |

`bytebase-rw` 的授权三段:

- 工作区级 `sqlEditorReadUser` — 全环境可读(写迁移 SQL 前得能看生产 schema)
- 工作区级 `projectDeveloper` — `bb.sheets.create`/`plans.create`/`issues.create`,即提工单
- **每个项目**级 `sqlEditorUser` + CEL 条件 `resource.environment_id in ["test"]` — test 环境直接跑 DDL/DML

⚠️ **CEL 条件绑定只能下在项目级**(工作区级 IAM policy 不支持 condition)。**新建 Bytebase 项目后须手动补这条绑定**,
否则该项目的 test 库对 `bytebase-rw` 不可写。当前已授:default / new-api-tdis / tipsy-backend-131q / tipsy-memory / tipsystudio。

⚠️ 提工单的三个权限是项目/工作区级、**无法按环境区分**。"生产只提单不直写"这条边界靠的是**写权限的 CEL 条件**,
不是工单权限本身——所以别把 `sqlEditorUser` 无条件授到工作区级,那会让生产库也能直写。

边界实测(经网关→plugin 真实链路):生产读通;生产直写被拒(`permission denied to access resources`);
test 环境 `CREATE TABLE`/`INSERT`/读回/`DROP TABLE` 全通;生产提工单成功且 rollout `NOT_STARTED`(SQL 未执行)。

## 测试

```sh
pnpm --filter @tool-bridge/plugin-bytebase test   # 14 例,真实 workerd,上游全 mock,默认离线
```
