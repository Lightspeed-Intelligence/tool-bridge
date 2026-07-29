# Guide:MCP 上游生产坑(会话复用与不合规上游)

> 用途:挂载/排查 `kind:mcp` 上游时的已知坑与可重跑排查手法。来源:2026-07-07 生产故障取证与修复(挂载 MetaMCP 后"过一段时间工具全部消失")+ 2026-07-08 同故障复发取证(初版防御被 KV 读缓存击穿)+ 2026-07-08 飞书官方 MCP 接入(自定义认证头)+ 2026-07-29 Bytebase 接入(强制 OAuth 上游改走服务账号,生产实例实测)。更新时机:MCP provider 会话机制变化或新上游坑出现时。

## 会话复用机制(gateway `providers/mcp.ts`)

- 上游签发的 `Mcp-Session-Id` 存 KV `mcpsession:<nodePath>`(**无 TTL**),后续请求带 sessionId 重建 transport,MCP SDK 对已设 sessionId 跳过 initialize(单趟往返)。
- 失效信号:上游 HTTP 400/404(`StreamableHTTPError`)→ 清缓存、完整握手重试一次并回填新会话。
- tools/list 结果另有 `toolcache:<path>` 缓存(TTL 300s;`~help?refresh=1` 强制重取)。两层缓存独立:refresh 只跳 toolCache,**不**跳会话。

## 坑:不合规上游对过期会话回 200 + 空列表(实测 MetaMCP)

- MCP spec 要求对过期 session 回 404;MetaMCP 空闲回收会话后把旧 session 当空会话,`tools/list` 正常返回空数组——网关侧毫无失效信号。
- 症状:节点 `~help` `cmds:[]`、调用一律 404「未知工具」,且不自愈(空列表还进 toolCache);注册面变更(触发 invalidate)前永不恢复。
- **防御(已实现)**:`list` 在"复用缓存会话 + 空列表"时视为可疑——清会话、**强制完整重握手**(`forceFresh`,不回读会话缓存)再取一次,仍空才相信;只重试一次不循环,真空列表的合规上游至多多付一趟握手。测试:gateway `tool.integration.test.ts`「mcp 会话复用:过期会话空列表防御」(默认离线,mock Streamable HTTP 上游)。
- **坑中坑:防御重试不得回读 KV(2026-07-08 复发根因)**。初版防御是"清会话(KV delete)→ 重试时 loadSession 回读 KV":同一请求内刚 get 过该 key,Cloudflare KV 边缘读缓存(≥60s)把刚删的旧会话又还回来 → 重试再次复用死会话 → 又拿到空列表 → 防御被击穿,空列表照进 toolCache。缓存命中是概率性的,故防御"有时自愈有时不能"——修复当天塞伪 session 验证通过、次日生产复发。修复:重试直接强制完整握手,不经会话缓存;钉死用例为同文件「KV 边缘读缓存吞掉 delete」(注入 delete 为 no-op 的 StateStore 模拟缓存窗口)。教训同 [workers-kv-pitfalls.md](workers-kv-pitfalls.md):**"删缓存后立刻回读"在 KV 上不成立,凡纠错路径都应绕开缓存读**。
- `call` 路径无此防御:工具名解析不到时走不到 call;上游对过期会话的 call 若返回 JSON-RPC 业务错误,网关无法与真实业务错误区分。

## 坑:需自定义认证头的上游(飞书官方 MCP)

- 端点 `https://mcp.feishu.cn/mcp`,认证不走 `Authorization: Bearer`:自定义头 `X-Lark-MCP-UAT`(用户凭证)或 `X-Lark-MCP-TAT`(应用凭证),token **原样注入**——挂载时 `--auth-header X-Lark-MCP-TAT --auth-scheme ''`(空串 scheme = 无前缀),config 即 `authHeader`/`authScheme`(与 http kind 同语义)。
- **必须带静态头 `X-Lark-MCP-Allowed-Tools`**(逗号分隔工具白名单,`--header` / config `headers`):缺失或写错时上游 `tools/list` **恒回空列表**——会触发上文的空列表防御(多付一趟完整重握手)后如实展示空。症状与"过期会话空列表"同貌,**排查时先查该头再怀疑会话层**(该头错时重握手也救不回来,这是与会话层故障的区分点)。
- 飞书 UAT/TAT 有效期约 2h;SecretStore 是静态存储,过期后上游回 401,须 `tb secret set` 手动续期,无自动刷新。**免人工续期的推荐路径是 `packages/plugin-feishu`**(tool-provider plugin,plugin 内 TAT 自动换发 + 上游 401 强制重换发自愈);其凭证不落 plugin:`tb secret set --name feishu-app`(值为 JSON `{"app_id","app_secret"}`)+ 挂载节点配 `authRef:"feishu-app"`,平台调用时经 `X-TB-Upstream-Auth` 注入。直挂 kind:mcp + 静态 TAT 适合一次性验证。
- 网关侧实现:每趟上游请求(initialize/notifications/tools list/call)合并 `headers` + 凭证头(凭证头覆盖同名静态头),见 gateway `providers/mcp.ts`;mock 上游断言用例在 gateway `tool.integration.test.ts`。

## 坑:只认 OAuth 且 DCR 白名单只放行 loopback 的上游(Bytebase)

- Bytebase 自托管的 `/mcp` **强制 OAuth bearer**:未带凭证回 401 + RFC 9728 `WWW-Authenticate`(`resource_metadata=.../.well-known/oauth-protected-resource/mcp`),`/.well-known/oauth-authorization-server` 宣告 DCR(`token_endpoint_auth_methods_supported:["none"]`)。托管 OAuth 直挂能跑,但其 DCR redirect 白名单只放行 loopback,**每次授权都得 `tb tool auth --local` 在本机开浏览器**;access token 1h、refresh 轮换在多 isolate 并发下会互相作废(见 current-state 2026-07-08 条)。
- **免人工授权的推荐路径是 `packages/plugin-bytebase`**:走 Bytebase **服务账号**而非 OAuth——`POST {baseUrl}/v1/auth/login` body `{email,password:<service_key>,web:false}` → `{token}`,该 token 是 audience `bb.user.access` 的 JWT,`/mcp` 的 authMiddleware 接受它(与 OAuth token 同等);plugin 内自动换发 + 401 强制重换发自愈。凭证不落 plugin:`tb secret set`(值为 JSON `{"email","service_key"[,"base_url"]}`)+ 挂载配 `authRef`。
- **换发接口的坑**:①响应体**只有 `token`,没有 expires_in**——过期时刻只能解 JWT `exp` claim(SA token 实测固定 1h);②Bytebase login 有**按 email 的失败锁定**(`checkPasswordLockout`),service_key 轮换后忘更新平台凭证会连续失败并可能锁号,故换发失败一律 `retryable:false` 不重试放大;③凭证若误配成人类账号且开了 MFA,login 回的是 `mfaTempToken` 而非 `token`(plugin 对此专门给提示)。
- **失效信号分层(2026-07-29 生产实测)**:坏/过期 token → **401**;有效 token + 陈旧 sessionId → **404**。两层各自纠错:401 走强制重换发令牌,404 走清会话完整重握手——**不可混淆**,否则会话过期会白白重换发令牌(反之令牌失效则永远修不好)。
- **坑(高危,复用会话必踩):Bytebase 把 access token 绑在 MCP session 上,自动续期会静默失效。** 上游在 `initialize` 时把当时的 token 存进 session context(`backend/api/mcp` 的 `withAccessToken`),之后 `tools/call` 用的是**会话里那个 token**,不看本次请求头。于是复用一条活过 1h 的会话时,即使客户端已换发新令牌,上游仍拿旧的去打内部 API。表现有三个迷惑点:①报错是 **HTTP 200 + ToolResult 文本 `access token expired`**,不是 401,所以"401 → 重换发"的自愈路径抓不到;②`search_api` 等纯本地索引工具照常可用,只有需要访问 Bytebase API 的工具(`query_database`/`get_schema`/`call_api`)全挂,故障面看着像上游抽风;③新建会话立刻就好,于是重启/换 isolate 会"自己恢复",极易误判为偶发。**修法**:把该文本也当失效信号,且**必须连会话一起丢**再重换发+重握手——只换令牌无效,新令牌进不了旧会话。写回归测试时注意:直接吊销全部 token 会让请求头也失效、退化成 401 路径,测不到这条;要让"头上的 token 有效 + 会话绑的已失效"分离(推进系统时钟越过刷新余量,让 plugin 自行换发进请求头)。
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
