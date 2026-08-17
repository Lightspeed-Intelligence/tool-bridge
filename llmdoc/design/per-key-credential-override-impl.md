# 详细技术方案:个人凭证覆盖(per-key credential override)

> 配套设计说明见 `per-key-credential-override.md`。本文给出可直接照做的实现细节:
> 确切的函数签名、类型改动、存储 schema、逐文件 diff 要点、测试与验证步骤。
> 已核对代码锚点(2026-08-12,分支 feat/hotfix)。

## 0. 已验证的前提

- 云效 `mcp/yunxiao`:`kind: mcp`,`authRef: "yunxiao"`,`authHeader: "Authorization"`,
  `authScheme: "Bearer"`,url `https://openapi-rdc.aliyuncs.com/ai/mcp`。上游支持个人 PAT。
- MCP 认证头组装点:`packages/gateway/src/providers/mcp.ts:306-315`(`makeAuth` 内,静态头形态)。
- 认证头语义 `authHeaderFor(config, cred)`:默认 `Authorization: Bearer <cred>`,
  受 `authHeader`/`authScheme` 调整。个人 token 走同一函数即可,无需特殊处理。
- `SecretStoreImpl`(`packages/core/src/secret/secretStore.ts`):
  - `set(name, value, now)` / `resolve(name)` / `list(opts)` / `delete(name)`;
  - `assertValidName` 只查非空 → **允许** `usercred:<owner>:<domain>` 这种带 `:` 的名字
    (owner 本身含 `:`,如 `user:ou_xxx`,也放行);
  - `:` 的禁令只在 `system/secret` builtin 的 `assertUserSecretName`(`builtin/secret.ts:22`),
    本方案的数据面绕开它,双方互不干扰。
- `CallContext.owner`(`core/src/types.ts:42`,值形如 `user:<openId>`)在两处都拿得到:
  - `providerFor(node, ctx, deps)`(`tbApp.ts:727`)→ 传 `ctx.owner` 给 mcp provider 做注入;
  - builtin `dispatch(cmd, args, ctx)`(`builtin/types.ts:20`)→ 数据面按本人 owner 圈定。
- `rotateLoginKey`(`feishuLogin.ts:372-402`):登录时删同 owner 旧 login key、发新 keyId。

## 1. 存储 schema

复用 SecretStore(AES-GCM,`TB_SECRET_ENCRYPTION_KEY`)。名字用保留命名空间:

```
usercred:<owner>:<credentialDomain>
```

- `owner`:调用方 SK 的 owner(`ctx.owner`,如 `user:ou_xxx`)。用 owner 不用 keyId
  ——open_id 跨登录稳定,rotate 换 keyId 后仍命中,**免除迁移逻辑**(见 §4)。
- `credentialDomain`:节点 config 声明的逻辑凭证域(如 `yunxiao`)。用域不用 authRef/节点路径
  ——节点迁移、authRef 改名都不影响个人凭证,是「接新 MCP」时可持续的维护单位。
- value:用户粘贴的个人 token 原文,加密落库。

不新增 KV 前缀、不改 `StateStore`。所有个人凭证与平台凭证同住 `secret:` 命名空间,
靠 `usercred:` 段区分。`system/secret` 的 list 会连带列出 `usercred:*`——**需在 secret builtin
的 list 过滤掉** `usercred:` 前缀(见 §5 附带改动),避免 admin 面泄露个人凭证的存在与 owner。

> owner 本身含 `:`(如 `user:ou_xxx`),`assertValidName`(§0)只查非空、放行;
> 完整 key 形如 `usercred:user:ou_xxx:yunxiao`,以 `usercred:` 前缀和末段 domain 界定。

## 2. 核心:mcp provider 的 per-key 回落

### 2.1 provider 接收 keyId

`createMcpProvider(config, secrets, opts)`(`mcp.ts:276`)的 `opts` 增加可选字段:

```ts
opts: {
  allowInsecure: boolean
  oauth?: { encryptionKey: string, store: StateStore }
  session?: McpSessionStore
  /** 调用方 owner(ctx.owner);与 credentialDomain 都在时查个人凭证覆盖节点默认 authRef。 */
  callerOwner?: string          // ← 新增
  /** 节点声明的凭证域(config.credentialDomain);缺省则不做个人凭证覆盖。 */
  credentialDomain?: string     // ← 新增
}
```

### 2.2 makeAuth 插入查找(唯一的行为改动)

`mcp.ts:306-315` 现状:

```ts
const h: Record<string, string> = { ...(config.headers ?? {}) }
if (config.authRef !== undefined) {
  const cred = await secrets.resolve(config.authRef)
  if (cred !== undefined) { const [hn, hv] = authHeaderFor(config, cred); h[hn] = hv }
}
```

改为「先个人后默认」:

```ts
const h: Record<string, string> = { ...(config.headers ?? {}) }
if (config.authRef !== undefined) {
  // 个人凭证优先:usercred:<owner>:<domain> 命中则以本人 token 落地。
  const personal = (opts.callerOwner !== undefined && opts.credentialDomain !== undefined)
    ? await secrets.resolve(`usercred:${opts.callerOwner}:${opts.credentialDomain}`)
    : undefined
  const cred = personal ?? await secrets.resolve(config.authRef)   // 回落节点默认
  if (cred !== undefined) { const [hn, hv] = authHeaderFor(config, cred); h[hn] = hv }
}
```

回落语义天然满足需求:个人凭证缺失(或节点未声明 domain)→ 用节点默认 token,行为与现状一致。

### 2.3 会话缓存的隔离(必须处理,否则串号)

`mcp.ts` 有跨请求的 MCP 会话缓存(`mcpsession:<nodePath>`,`withSession`/`saveSession`)。
上游会话是**在某把 token 下 initialize 出来的**;若 A(个人 token)initialize 的会话被
B(管理员 token)复用,B 的调用会以 A 的身份落地——安全事故。

对策:会话缓存 key 从 `nodePath` 细化为 `nodePath + 凭证指纹`。凭证指纹取「实际注入的 token 的
sha256 前若干位」(不落明文,只作分桶键)。`session.nodePath` 相关逻辑(`mcp.ts:289`、
`saveSession`/`loadSession`/`clearSession`)改为接收一个 `sessionKey`,由 `makeAuth` 算出的
指纹参与拼装。个人 token 与管理员 token 各自一条会话,互不复用。

> 备选(更简单但更糙):MCP 节点一旦有任何个人凭证覆盖,就对该节点禁用会话缓存
> (每次 forceFresh)。实现小,但牺牲所有用户的会话复用性能。推荐用指纹分桶。

### 2.4 providerFor 透传 owner + domain

`tbApp.ts:733-742` 构造 mcp provider 处,`ctx` 在手,透传两个字段:

```ts
const cfg = node.config as McpConfig
return createMcpProvider(cfg, deps.secrets, {
  allowInsecure: insecure,
  session: { store: deps.state, nodePath: node.path },
  callerOwner: ctx.owner,                                   // ← 新增
  ...(cfg.credentialDomain !== undefined
    ? { credentialDomain: cfg.credentialDomain } : {}),     // ← 新增
  ...(deps.encryptionKey !== undefined
    ? { oauth: { store: deps.state, encryptionKey: deps.encryptionKey } }
    : {}),
})
```

> `http` 节点(`createHttpProvider`,`tbApp.ts:744-746`)可同款支持,P3 再做。

## 3. 数据面:个人凭证读写端点

### 3.1 新 builtin 模块 `usercred`

新文件 `packages/core/src/builtin/usercred.ts`,实现 `BuiltinModule`。挂载为节点
`system/my-credentials`(kind `builtin`,module `usercred`)。

依赖注入:`{ secrets: SecretStoreImpl, now: () => Timestamp }`。cmd 表:

| cmd | 入参 | 行为 | scope |
|---|---|---|---|
| `set` | `{ domain: string, value: string }` | 写 `usercred:<ctx.owner>:<domain>`,value 加密不回显 | 见 §3.3 |
| `list` | `{}` | 列本人的 domain(前缀扫 `usercred:<ctx.owner>:`,只出 domain+updatedAt) | 见 §3.3 |
| `delete` | `{ domain: string }` | 删 `usercred:<ctx.owner>:<domain>` | 见 §3.3 |

`dispatch(cmd, args, ctx)` 内以 `ctx.owner` 拼 key,**用户无法指定他人身份**——
入参只有 `domain`,owner 一律取自 ctx。这是本人隔离的关键。

list 需要按 `usercred:<owner>:` 前缀翻页(`SecretStoreImpl.list` 只从 `secret:` 全量翻,
需在模块内自行 filter 前缀;或给 SecretStore 加一个带前缀的内部 list——倾向前者,不动 core API)。
返回项把 `usercred:<owner>:` 剥掉,只回末段 domain,**绝不回 value**。

`domain` 入参校验:非空、不含 `:`(域名段不该带 `:`,防止越权拼到
`usercred:<owner>:plugin-token:x` 这类保留名;owner 段来自 ctx 不受用户控制)。

### 3.2 装配

- `createBuiltins`(`builtin/index.ts:67`)加 `modules.set('usercred', createUserCredModule({ secrets: deps.secret, now }))`;
  `secret` 依赖已在 `BuiltinDeps`,无需新增注入点。
- 节点 `system/my-credentials` 由 bootstrap 幂等建立(参照现有 `system/sk`、`system/secret`
  的 bootstrap 注册),config `{ kind: 'builtin', module: 'usercred' }`。

### 3.3 权限模型(与 admin 面的关键区别)

`system/secret` 是 admin 全局面。`system/my-credentials` 不是——它要「任何登录 SK 都能
读写**自己的**」。两种实现路线:

- **路线 A(推荐,零特权)**:cmd scope 声明为普通 `call`(或专门的 `self`),节点挂在
  登录 SK 默认 scope 覆盖得到的路径下(`defaultLoginScopes`,`feishuLogin.ts`)。隔离不靠 scope,
  靠 `dispatch` 内 `ctx.owner` 硬圈定——A 的 SK 调用永远只碰 `usercred:<A的owner>:*`。
  需确认/调整 `defaultLoginScopes` 让登录 SK 能 call `system/my-credentials`。
- **路线 B**:新增一个 `self` scope 语义。改动大,不推荐。

选 A。安全性来自「owner 来自 ctx 而非入参」,而非 scope 粒度。

## 4. 为什么不需要迁移(open_id 维度的红利)

个人凭证键用 `ctx.owner`(即 `user:<openId>`)而非 keyId。open_id 跨登录稳定,
`rotateLoginKey`(`feishuLogin.ts:372`)换发新 keyId 时 owner 不变,个人凭证**自动仍然命中**。
因此:

- `rotateLoginKey` **无需改动**,登录回调也无需搬运逻辑;
- 没有 best-effort 迁移的失败面;
- 接的上游再多也不增加登录时的搬运负担。

(对比:若选 keyId 作维度,就得在每次 rotate 时按 `usercred:<oldKeyId>:` 前缀
list→resolve→set 到新 keyId→delete 旧的,明文内存中转、best-effort 可失败——open_id
维度整块免除。这正是选 owner 而非 keyId 的核心理由。)

## 5. 附带改动:secret builtin 的 list 过滤

`system/secret` 的 `list`(`builtin/secret.ts`,委托 `SecretStoreImpl.list`)会连带列出
`usercred:*`,泄露个人凭证存在性与 owner。改动:secret 模块 list 结果 filter 掉 `usercred:`
前缀(和它已有的 `plugin-token:` 等保留项处理保持一致)。core 的 `SecretStoreImpl.list`
保持不变(它是内部 API)。

## 6. Dashboard(P2)

飞书登录后(SK 在手)新增「我的凭证」页:

- 列出节点 config 标了 `allowUserCredential: true` 的域(如云效),
  状态显示「已配置(个人)/ 未配置(回落管理员)」——状态来自 `system/my-credentials` 的 list。
- 「填写」弹窗:粘贴个人 token → 调 `system/my-credentials` set(入参 domain=节点的 credentialDomain)。
  明文纪律同 SK 签发页(不回显、不入 URL、不进日志,提交即弃)。
- 「清除」→ delete,回落管理员。

节点 config 加可选 `credentialDomain?: string`(个人凭证的域)+ `allowUserCredential?: boolean`
(是否展示可填)。Dashboard 只据此决定展示范围与填哪个 domain,网关侧不因 `allowUserCredential`
改变注入逻辑(注入只看「有 credentialDomain 且个人凭证命中 → 用个人,否则回落」,
`allowUserCredential` 纯为 UI 白名单)。

## 7. 逐文件改动清单

| 文件 | 改动 | 分期 |
|---|---|---|
| `packages/gateway/src/providers/mcp.ts` | `opts.callerOwner` + `credentialDomain`;`makeAuth` per-owner 回落;会话缓存 key 加凭证指纹 | P1 |
| `packages/gateway/src/tbApp.ts` | `providerFor` 传 `callerOwner: ctx.owner` + 节点 `credentialDomain`;`createBuiltins` 装配 `usercred` | P1 |
| `packages/core/src/builtin/usercred.ts`(新) | 个人凭证数据面 set/list/delete,本人 owner 圈定 | P1 |
| `packages/core/src/builtin/index.ts` | 装配 `usercred` 模块;导出 factory | P1 |
| `packages/core/src/builtin/secret.ts` | list 过滤 `usercred:` 前缀 | P1 |
| `packages/gateway/src/bootstrap.ts` | 幂等建 `system/my-credentials` 节点 | P1 |
| 节点 config 类型(McpConfig 等) | P1 加 `credentialDomain?: string`;P2 加 `allowUserCredential?: boolean` | P1/P2 |
| `packages/dashboard/src/pages/*`(新) | 「我的凭证」页 | P2 |

(注意:owner 维度免除了 rotate 迁移——`feishuLogin.ts` 无需改动。)

## 8. 测试点

单元(core):
- `usercred` dispatch:set/list/delete 只作用于 `usercred:<ctx.owner>:*`;
- 传不同 ctx.owner → 互相读不到、删不到;list/set 永不回显 value;
- `domain` 入参含 `:` → invalid_argument(防越权拼保留名);
- secret 模块 list 不含 `usercred:` 前缀项。

单元(gateway/mcp):
- `callerOwner` + `credentialDomain` 命中个人凭证 → 注入头用个人 token;缺失(或节点无 domain)→ 回落 authRef 默认;
- 无 authRef 的节点不受影响;
- 会话缓存:个人 token 与管理员 token 分桶,不复用彼此会话(指纹不同 → 不同 sessionKey)。

单元(feishuLogin):
- 重新登录换 keyId 后,同 owner 的个人凭证仍命中(无迁移逻辑,owner 不变即可)。

集成/真机:
- 用户经 CLI/API 写入云效 PAT(domain=yunxiao)→ 调 `mcp/yunxiao` 写操作 → 云效侧记录为本人;
- 未写入的用户 → 仍走管理员 token,不阻断。

## 9. 分期

- **P1(核心,CLI 可验证)**:mcp.ts per-owner 回落 + 会话分桶 + `usercred` 数据面 +
  secret list 过滤 + 节点 `credentialDomain` + bootstrap 建节点。做完即可用 CLI 写云效 PAT
  验证按人落地。(无 rotate 迁移——owner 维度免除。)
- **P2(体验)**:节点 `allowUserCredential` 标记 + Dashboard「我的凭证」页。
- **P3(可选)**:`http` provider 同款支持;个人凭证 TTL/到期提醒。

## 10. 建议先做的最小验证(P0 spike)

在铺 P1 全量前,先验证云效 PAT 经 Bearer 注入真能按人落地、无额外 header/scheme 坑:

1. 只改 `mcp.ts` 的 `makeAuth`(加 callerOwner + credentialDomain + 回落)与 `tbApp.ts` 透传
   (约 10 行);spike 阶段 domain 可先硬编码 `yunxiao`,不必先加节点 config 字段;
2. 手工往 KV 塞一条 `secret:usercred:user:<某人的openId>:yunxiao`(用 `system/secret` 塞不进——
   有 `:` 守卫;临时用 wrangler kv 直写一条加密记录,或临时放宽走 core set);
3. 用那把人(其登录 SK)调云效一个 whoami / 建工作项类的写操作,确认落地身份是本人;
4. 通过 → 铺 P1;不通 → 先解决上游 token 形态问题(scheme/header/权限)。

> 会话缓存分桶(§2.3)在 spike 阶段可先用「有个人凭证就 forceFresh」的糙版跳过,
> P1 再上指纹分桶。
