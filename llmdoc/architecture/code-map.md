# 代码地图

## 根入口

| 路径 | 用途 |
|---|---|
| `package.json` | 根验证、构建、部署、smoke 脚本 |
| `scripts/release-plan.mjs` | public package 发布计划与顺序 |
| `scripts/provision.mjs` | Cloudflare 资源创建与账户配置回填 |
| `scripts/verify-*.ts` | MCP、Search、设备、plugin、吊销的 opt-in 验收 |
| `.github/workflows/` | CI 与逐包发布工作流 |

## core

| 主题 | 路径/符号 |
|---|---|
| 公共类型与 NodeKind | `packages/core/src/types.ts` |
| 授权与 SK | `auth/authorizer.ts`、`auth/sk.ts`、`auth/secretRef.ts` |
| 树与 registry | `tree/registry.ts`、`tree/path.ts`、`builtin/registry.ts` |
| builtin 装配 | `builtin/index.ts` |
| 外部 plugin 注册 | `builtin/plugin.ts`、`plugin/manifest.ts`、`plugin/contract.ts` |
| 内置 catalog | `builtin/catalog.ts`、`plugin/catalog.ts` |
| Search 契约 | `search/types.ts`、`search/sqlSearchIndex.ts` |
| 设备协议 | `device/frames.ts`、`device/session.ts`、`device/client.ts` |
| HTBP 表示 | `htbp/helpDsl.ts`、`helpMarkdown.ts`、`tree.ts` |

## packages/plugin-bytebase — Bytebase tool-provider Plugin(private,CF Worker)

<!-- TODO(sync): 上游已把内置 provider 收进单体包 `packages/plugins`(见下方 ## plugin 段);Lightspeed fork 仍以独立 `packages/plugin-feishu`/`plugin-meego`/`plugin-bytebase` CF Worker 形态部署外部 tool-provider。二者是不同层次(内置 catalog vs 外部 HTTP plugin),但打包边界需人工复核对齐。 -->


Bytebase 自托管 MCP(`{baseUrl}/mcp`)的 tool-provider/v1 plugin,解决**托管 OAuth 须人工本机授权**问题:Bytebase `/mcp` 只认 OAuth bearer 且其 DCR 白名单只放行 loopback(直挂 `kind:mcp` 得走 `tb tool auth --local` 开浏览器,access token 1h 过期、refresh 轮换在多 isolate 并发下会互相作废)。本 plugin 改走**服务账号**:SA 的 `service_key` 换发访问令牌并缓存,401 强制重换发——零人工授权、永不过期。结构照抄 plugin-feishu(同一模式第三例)。

| 文件 | 管什么 |
|---|---|
| `src/index.ts` | 契约面 GET `/healthz` / `/~describe` / `/~help` + POST `/` envelope(List/Get/Call);`PLUGIN_TOKEN` Bearer 鉴权;`RequestDedupe` 幂等;**上游凭证不自持**:从 `X-TB-Upstream-Auth` 读(base64url JSON `{"email","service_key"[,"base_url"]}`);实例地址 = 凭证 `base_url` > `BYTEBASE_BASE_URL`,皆缺 → unavailable;**上游 401 → 强制重换发令牌重试一次**(`withTokenRetry`);`EFFECT_BY_NAME` 按名兜底 effect(**Bytebase 3.19.0 的 tools/list 不带 annotations**,不兜底则 destructive 二次确认失效);白名单**双闸**(List 过滤 + Call 拒绝,知道名字也绕不过) |
| `src/token.ts` | SA 访问令牌换发(`POST /v1/auth/login` body `{email,password:<service_key>,web:false}` → `{token}`)+ isolate 内存缓存(**按 `<baseUrl>\|<email>\|sha256(service_key)前16hex` 键控** —— key 摘要必须进键,2026-07-29 生产实测:漏了它则错 service_key 会命中同 email 的有效缓存并返回 200,既破坏"plugin 无凭证即空壳"也让 key 轮换延迟到旧令牌到期;多实例/多账号挂载不串号;刷新余量 5min)。响应**无 expires_in**,到期时刻从 JWT `exp` claim 解(`decodeExp`,只解不验签;读不到回落 30min 保守 TTL);实测 SA token audience `bb.user.access`、固定 1h。换发失败一律 `retryable:false`——Bytebase login 有按 email 的失败锁定,不重试放大 |
| `src/bytebaseMcp.ts` | MCP SDK Streamable HTTP client:标准 `Authorization: Bearer`;isolate 内存会话复用(键与令牌缓存**同粒度**,含 key 摘要 —— 换了 key 即另一条身份链,会话不得复用;400/404 清会话重握手一次);401 原样抛出交给 index 重换发;`CfWorkerJsonSchemaValidator`(workerd 禁 eval,同 gateway 坑) |
| `test/plugin.integration.test.ts` | 14 例集成测试(真实 workerd;mock login 与 MCP 上游,默认离线):令牌换发与缓存命中、401 强制重换发自愈、**会话 404 重握手不误触发换发**、凭证头缺失/坏形状/缺字段、错 service_key 只打一次 login、**错 key 不得蹭同 email 缓存令牌(生产实测回归)**、白名单双闸、多账号不串号、`base_url` 覆盖与归一、`decodeExp` |
| env(`wrangler.jsonc`) | secrets:仅 `PLUGIN_TOKEN`;vars:`BYTEBASE_BASE_URL`、`BYTEBASE_ALLOWED_TOOLS`(留空 = 放行上游全部工具) |

**权限/审计边界(与 plugin-feishu 不同的要点)**:SA 继承自己在 Bytebase 的 IAM 角色,审计日志记在该 SA 名下而非真实调用者——第一道闸是 Bytebase 侧授权(只读用途只给 `sqlEditorReadUser` 之类),`BYTEBASE_ALLOWED_TOOLS` 是 plugin 侧补充的第二道。若要做「谁调用记谁」需另走 plugin-meego 的 `mountConfig` 身份映射路子(Bytebase 侧要求每人一个 SA,当前未做)。

**权限分级用「一份部署 + 多个挂载」表达**(2026-07-29 落地):令牌与会话缓存键含 service_key 摘要,故同一 Worker 可同时服务不同权限的 SA。生产实例上挂了两个节点(与其他 plugin 同级于 `plugins/` 下):`plugins/bytebase`(只读 SA)与 `plugins/bytebase-rw`(test 可写 + 全环境提单 SA)。`plugins/bytebase-rw` 的"生产只提单不直写"由**项目级 CEL 条件** `resource.environment_id in ["test"]` 实现——注意 CEL 条件绑定只能下在项目级(工作区级不支持),新建项目须手动补;而提工单的三个权限(`bb.sheets.create`/`plans.create`/`issues.create`)是项目/工作区级、无法按环境区分,所以环境边界只能靠写权限那条条件。

## app

| 主题 | 路径/符号 |
|---|---|
| 宿主注入类型 | `packages/app/src/deps.ts` / `TbAppDeps` |
| app 组装 | `tbApp.ts`、`bootstrap.ts` |
| 路径与节点分发 | `paths.ts`、`toolNodes.ts`、`contextNodes.ts`、`deviceNodes.ts` |
| 路由 | `routes/` |
| MCP 上游 | `providers/mcp.ts`、`mcpServer.ts` |
| plugin 调用 | `providers/pluginClient.ts` |
| remote 联邦 | `providers/remote.ts`、`federation.ts` |

## 宿主与客户端

- Workers：`packages/gateway/src/app.ts` 装配 Env；`deployEntry.ts` 全量装内置 catalog；`kvStateStore.ts`、`search/d1SearchIndex.ts`、`deviceSession.ts` 是适配器。
- Node：`packages/server/src/main.ts`、`server.ts`、`config.ts`；SQLite/FS/ws 实现在同包。
- SDK：`packages/sdk/src/toolBridge.ts`、`deviceClient.ts`、`types.ts`。
- CLI：`packages/cli/src/program.ts` 装配命令；`commands/` 按业务拆分；`http.ts` 统一调用与错误。
- Dashboard：`packages/dashboard/src/lib/` 是 API/query/session；`pages/system/` 是系统控制面；`components/` 是共享 UI。

## plugin

- 作者面：`packages/plugin-sdk/src/index.ts`。
- 内置装配：`packages/plugins/src/registry.ts`。
- 生成产物：`catalog.generated.ts`、`registry.generated.ts`。
- 生成器：`packages/plugins/scripts/generateCatalog.ts`、`generateRegistry.mjs`。
- 迁移闸门：`packages/plugins/test/migration/`、`migration-fingerprints.json`。

## 查找习惯

先从符号而不是历史文档搜：

```sh
rg "createTbApp|TbAppDeps|BUILTIN_MODULES" packages/app
rg "CatalogListItem|exportDetails" packages/core packages/cli packages/dashboard
rg "NodeKind|NODE_KINDS" packages/core
rg "system/catalog|system/plugin" packages llmdoc
```

精确测试数、行数、bundle 字节和生成目录规模不属于代码地图；需要时从当前工作树实查。
