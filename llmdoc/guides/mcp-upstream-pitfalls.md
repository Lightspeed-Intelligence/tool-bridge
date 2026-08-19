# MCP 上游互操作

MCP 是外部协议兼容面。项目内部历史状态可删，但现代/旧版 MCP 服务端的真实差异必须保留。

> 用途:挂载/排查 `kind:mcp` 上游时的已知坑与可重跑排查手法。来源:2026-07-07 生产故障取证与修复(挂载 MetaMCP 后"过一段时间工具全部消失")+ 2026-07-08 同故障复发取证(初版防御被 KV 读缓存击穿)+ 2026-07-08 飞书官方 MCP 接入(自定义认证头)+ 2026-07-29 Bytebase 接入(强制 OAuth 上游改走服务账号,生产实例实测)。更新时机:MCP provider 会话机制变化或新上游坑出现时。

## 当前会话模型

- 客户端按 modern/legacy 两个 era 协商，判定缓存键为 `mcpera:<nodePath>`。
- modern discovery 按上游返回的 TTL 缓存；legacy era 使用本地有限 TTL。
- 工具清单继续进入 `toolcache:<nodePath>`；工具调用结果永不缓存。
- v2 不复用上游 session，不存在 `mcpsession` 或 `forceFresh` 控制面。
- 入站 `/~mcp` 是无状态适配器，不依赖 `Mcp-Session-Id`。

## 互操作边界

- 初次 discovery 先探测服务端能力，再按 era 选择请求形状；不要仅凭版本字符串猜测。
- 严格 capabilities 用于阻止服务端未声明的能力；未知扩展字段仍按协议的前向兼容规则处理。
- OAuth 与自定义认证头必须在 redirect 时遵守同源限制，不能把凭据转发给新 origin。
- HTTP 上游默认 HTTPS；本地 stub 需要显式 `TB_ALLOW_INSECURE_HTTP=true`。
- 错误要归一为稳定 HTBP 错误，但保留足够的上游分类用于排障，不能泄漏 token/headers/body 中的密钥。

## 验证层次

1. provider 单测：era 探测、TTL、能力约束、错误映射。
2. app/gateway 集成：`~help`、单工具披露、envelope 调用、缓存命中。
3. consumer E2E：用真实 MCP client 连接 `/~mcp`，验证初始化、发现与调用。
4. 真实上游仅在明确提供 URL/凭据时运行 `pnpm verify:mcp`。

不要为了单个失常服务端加入无边界 fallback。先确认它是协议时代差异还是上游 bug，再把兼容限制在 provider 层并加回归测试。

## 坑:只认 OAuth 且 DCR 白名单只放行 loopback 的上游(Bytebase)

- Bytebase 自托管的 `/mcp` **强制 OAuth bearer**:未带凭证回 401 + RFC 9728 `WWW-Authenticate`(`resource_metadata=.../.well-known/oauth-protected-resource/mcp`),`/.well-known/oauth-authorization-server` 宣告 DCR(`token_endpoint_auth_methods_supported:["none"]`)。托管 OAuth 直挂能跑,但其 DCR redirect 白名单只放行 loopback,**每次授权都得 `tb tool auth --local` 在本机开浏览器**;access token 1h、refresh 轮换在多 isolate 并发下会互相作废(见 current-state 2026-07-08 条)。
- **免人工授权的推荐路径是 `packages/plugin-bytebase`**:走 Bytebase **服务账号**而非 OAuth——`POST {baseUrl}/v1/auth/login` body `{email,password:<service_key>,web:false}` → `{token}`,该 token 是 audience `bb.user.access` 的 JWT,`/mcp` 的 authMiddleware 接受它(与 OAuth token 同等);plugin 内自动换发 + 401 强制重换发自愈。凭证不落 plugin:`tb secret set`(值为 JSON `{"email","service_key"[,"base_url"]}`)+ 挂载配 `authRef`。
- **换发接口的坑**:①响应体**只有 `token`,没有 expires_in**——过期时刻只能解 JWT `exp` claim(SA token 实测固定 1h);②Bytebase login 有**按 email 的失败锁定**(`checkPasswordLockout`),service_key 轮换后忘更新平台凭证会连续失败并可能锁号,故换发失败一律 `retryable:false` 不重试放大;③凭证若误配成人类账号且开了 MFA,login 回的是 `mfaTempToken` 而非 `token`(plugin 对此专门给提示)。
- **失效信号分层(2026-07-29 生产实测)**:坏/过期 token → **401**;有效 token + 陈旧 sessionId → **404**。两层各自纠错:401 走强制重换发令牌,404 走清会话完整重握手——**不可混淆**,否则会话过期会白白重换发令牌(反之令牌失效则永远修不好)。
- **上游 `tools/list` 不带 annotations**(3.19.0 实测只有 name/description/inputSchema):平台侧 effect 与 destructive 二次确认全靠它,plugin 内须按工具名兜底(`propose_database_change` → destructive、`query_database`/`get_schema` → read)。注意别在 mock 里写 `annotations: null` —— MCP SDK 的 schema 校验会直接报 `expected object, received null`,而真实上游是**整个字段缺省**。
- **权限/审计边界**:SA 继承其在 Bytebase 的 IAM 角色,审计日志记在 SA 名下而非真实调用者。第一道闸是 Bytebase 侧授权(只读用途只给 `sqlEditorReadUser` 之类),plugin 侧 `BYTEBASE_ALLOWED_TOOLS` 是第二道且**必须双闸**(List 过滤 + Call 拒绝;只在 List 过滤则知道工具名即可绕过)。生产实测(SA 只有 `sqlEditorReadUser`,白名单留空放行全部工具):`query_database`/`get_schema`/`search_api` 通,`propose_database_change` 被上游拒 `PERMISSION_DENIED: you don't have permission to create sheets`——**只给只读角色时不必靠白名单挡写**,白名单的价值是减少工具噪音与纵深防御。
- **权限分级:一份 plugin 部署 + 多个挂载,不要靠一个"大权限 SA"**(2026-07-29 落地)。缓存键含 service_key 摘要后,同一 Worker 可同时服务不同权限的 SA,所以按用途拆挂载点最省事:`plugins/bytebase`(只读 SA)/ `plugins/bytebase-rw`(test 可写 + 提单 SA)。要"test 环境可直接改、生产只能提工单"时的两个坑:①**CEL 条件绑定只能下在项目级**(proto 明写 condition "only used in the project IAM policy"),`resource.environment_id in ["test"]` 得逐项目授,**新建项目必须手动补**否则该项目 test 库不可写;②**提工单的三个权限(`bb.sheets.create`/`plans.create`/`issues.create`)是项目/工作区级、无法按环境区分**——所以环境边界只能落在**写权限**那条条件上,千万别把 `sqlEditorUser` 无条件授到工作区级(那样生产库也能直写,工单流程就被绕过了)。
- **CEL 条件不影响另一条无条件绑定的读权限**(实测):给 `sqlEditorUser` 加了 `environment_id in ["test"]` 后,生产库仍可读——因为读权限来自另一条无条件的工作区级 `sqlEditorReadUser` 绑定。多条绑定是并集,按用途分开授比往一条绑定上堆条件清楚。
- **凭证缓存键必须含 service_key 摘要**(2026-07-29 生产实测踩到):按 `<baseUrl>|<email>` 键控看似够用(多实例/多账号不串号),但**错 service_key 会命中同 email 的有效缓存并成功返回** —— 于是"plugin 无凭证即空壳"被打破(泄漏 PLUGIN_TOKEN + 猜到 SA 邮箱即可白蹭令牌),且 service_key 轮换在旧令牌到期前不生效。修法:键加 `sha256(service_key)` 前 16 hex,MCP 会话键同粒度(换 key 即另一条身份链,会话不复用)。**推广到所有此类 plugin**:凡"凭证由平台每次注入 + plugin 侧缓存换发结果"的形态,缓存键都必须覆盖**全部**入参凭证字段,漏一个即是隔离缺口。

## 排查手法(生产可重跑)

- **区分缓存层**:`~help?refresh=1` 后仍异常 ⇒ 问题在会话层或上游本身,不在 toolCache。
- **手动强制重握手**:对节点做幂等 registry update(patch 同值 description)触发 `invalidateToolCache` + `invalidateMcpSession`;若恢复 ⇒ 根因锁定会话层。这也是线上应急恢复手段。
- **复现故障态**:`npx wrangler kv key put --namespace-id <tb-kv id> "mcpsession:<path>" '{"sessionId":"bogus","updatedAt":"<iso>"}' --remote` 塞伪会话,再打 `~help?refresh=1` 验证自愈(2026-07-07 生产实测:工具列表恢复、KV 自动回填新 session)。
- 上游凭据(SecretStore)只写不读拿不到明文,对上游直接取证只能无凭据探边界(看 401 形状);主要靠网关侧对照实验(旧会话 vs 新会话)定位。
