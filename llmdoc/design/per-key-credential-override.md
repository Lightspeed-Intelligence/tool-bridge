# 设计:个人凭证覆盖(per-key credential override)

## 目标

云效(`mcp/yunxiao`)等 MCP 节点现在全员共用一把管理员 token,操作无法归属到个人。
让飞书登录后的用户可以**写入自己的上游凭证**;调用时:

- 该用户填了个人凭证 → 上游以本人 token 落地(身份 + 权限都是本人);
- 没填 → 回落节点默认 `authRef`(即现状,不阻断)。

前置已确认:云效(`https://openapi-rdc.aliyuncs.com/ai/mcp`)支持个人 token(PAT),
可按人签发。即上游有可注入的个人凭证,方案可行性下限成立。

## 为什么不能照搬 Meego 的做法

Meego(`plugins/meego`,`kind: tool`)是「固定 plugin 凭证 + 请求体里的 `X-USER-KEY`」区分操作人,
user_key 是**身份标识不是密码**,明文写进节点 `providerConfig.userKeys` 风险可控。

云效(`kind: mcp`)是把 `authRef` 解析出的 token 直接注入 `Authorization: Bearer`
(`packages/gateway/src/providers/mcp.ts:308-313`),token **既是身份又是密码**。
所以个人凭证必须像 SK 明文一样加密落库、只写不读、只能本人写自己的——不能写进节点配置。

## 维度选型:open_id × credentialDomain(而非 keyId × authRef)

这是本方案能「以后接任意 MCP 都不加维护负担」的关键。映射本质是一条二维关系
「谁 × 哪个上游」,两个维度都不能用直觉的第一选择:

**「谁」用 open_id,不用 keyId。** keyId 随登录 rotate 变(`rotateLoginKey` 每次换发),
用 keyId 作维度就必须在每次登录时搬运个人凭证,接的上游越多、搬得越多、还是 best-effort 会失败。
open_id 是飞书身份、跨登录稳定,用它**根本不需要迁移**。注入时 `ctx.owner` 就是 `user:<openId>`
(登录 SK 的 owner 由 `loginOwner` 写入),直接可得,无需额外反查。

**「哪个上游」用 credentialDomain,不用 authRef 或节点路径。** authRef 是凭证引用名、节点路径是
物理位置,两者都会变(改名、迁移、一个上游挂多路径)。引入一个显式的**凭证域** `credentialDomain`
作为逻辑身份域:云效读写多个节点都标 `credentialDomain: "yunxiao"`,GitHub 的标 `"github"`。
用户按域填一次,该域下所有节点共享;节点路径变了、authRef 改名了,个人凭证都不受影响。
这才是「接新 MCP」时可持续的维护单位。

## 存储

复用现有 `SecretStoreImpl`(AES-GCM,`TB_SECRET_ENCRYPTION_KEY`,
`packages/core/src/secret/secretStore.ts`)。个人凭证用**保留命名空间**的 secret name:

```
usercred:<owner>:<credentialDomain>      → 加密的个人 token
         └ ctx.owner,如 user:ou_xxx     └ 节点 config 声明的凭证域,如 yunxiao
```

`usercred:` 前缀命名空间和 `plugin-token:<id>` 同款,已被 `system/secret` 节点面的
`assertUserSecretName`(`builtin/secret.ts:22`)挡在 admin 手工操作之外——防止有人经
`system/secret` 伪造或误删个人凭证。个人凭证只能经下面的专用数据面读写。

(owner 本身含 `:`,如 `user:ou_xxx`,SecretStore 的 `assertValidName` 只查非空、放行;
`:` 的禁令只在 `system/secret` 的 admin cmd 面,数据面绕开。)

## 网关改动

### 1. 解析上游认证头时插入 per-key 查找

`providers/mcp.ts` 组装静态头那段(当前):

```ts
if (config.authRef !== undefined) {
  const cred = await secrets.resolve(config.authRef)          // 节点默认
  if (cred !== undefined) { const [hn, hv] = authHeaderFor(config, cred); h[hn] = hv }
}
```

改为:节点标了 `credentialDomain` 时,先查 `usercred:<ctx.owner>:<credentialDomain>`,
命中用个人的,否则回落 `config.authRef`。owner 从 `CallContext.owner`(`core/src/types.ts:42`)取
——`providerFor`(`tbApp.ts:733`)构造 provider 时 `ctx` 在手,把 `ctx.owner` 与节点的
`credentialDomain` 透传进 provider 的 auth 选项即可。

回落语义天然满足需求:个人凭证缺失(或节点没标 domain)→ 用节点默认 token,行为不变。

### 2. 数据面:个人凭证读写端点

新增一个 builtin 模块(如 `usercred`,挂 `system/my-credentials`),cmd:

- `set { domain, value }` — 写 `usercred:<ctx.owner>:<domain>`,value 加密不回显;
- `list {}` — 列出**本人**已配置的 domain 名(只出 domain + updatedAt,绝不出 value);
- `delete { domain }` — 删本人该域,回落节点默认。

关键约束:**scope 不是 admin**,而是「本人」——用 `ctx.owner` 圈定操作范围,
入参只有 `domain`,owner 一律取自 ctx,任何登录 SK 都只能读写 `usercred:<自己的owner>:*`,
无法触及他人。这与 `system/secret`(admin 全局)是两个不同的面。

### 3. 哪些节点「支持个人凭证」

节点 config 加两个可选字段:`credentialDomain`(个人凭证按哪个逻辑域存查)与
`allowUserCredential: true`(Dashboard 是否展示可填)。接入新 MCP 时管理员标一次即可
(云效标 `domain: "yunxiao"` 开;r2-presign 这类平台级凭证不标,保持全员共用)。
Dashboard 据 `allowUserCredential` 决定给用户展示哪些域可填。

## Dashboard 改动

飞书登录后(SK 已在手),新增「我的凭证」页:

- 列出标了 `allowUserCredential` 的域(如云效),显示「已配置(个人)/ 未配置(回落管理员)」;
- 「填写」弹窗粘贴个人 token → 调 `system/my-credentials` 的 `set`;
- 明文纪律与 SK 签发页一致:不回显、不入 URL、不进日志,提交后即弃。

接了新 MCP、管理员标了域,它就自动出现在每个用户的可填列表里——用户自助,零逐人配置。

## 为什么不需要迁移(open_id 维度的红利)

个人凭证键用 `ctx.owner`(即 `user:<openId>`)而非 keyId。open_id 跨登录稳定,
`rotateLoginKey` 换发新 keyId 时 owner 不变,个人凭证**自动仍然命中**,无需搬运。
(若当初选 keyId 作维度,就得在每次登录 rotate 时按前缀 list→复制→删除,接的上游越多越重、
且 best-effort 会失败——open_id 维度直接免除这整块逻辑。)

## 安全要点

- 个人 token 是真机密:加密落库、只写不读、只能本人写自己的(靠 `ctx.owner` 圈定,非 admin)。
- 泄露面比现状更小:个人 token 权限通常 ≤ 管理员,按人隔离优于「全员共用一把管理员 token」。
- 保留命名空间 `usercred:` 已被 `assertUserSecretName` 挡住 admin 手工面,双保险。
- **会话缓存隔离**:MCP 会话按注入凭证分桶,个人 token 与管理员 token 不复用彼此会话
  (详见 impl 文档 §2.3)——否则会串号(A 的会话被 B 复用 → B 以 A 身份落地)。

## 涉及文件

| 文件 | 改动 |
|---|---|
| `packages/gateway/src/providers/mcp.ts` | auth 头解析插入 per-owner 查找;auth 选项加 owner + domain;会话缓存按凭证分桶 |
| `packages/gateway/src/tbApp.ts` | `providerFor` 透传 `ctx.owner` + 节点 `credentialDomain`;注册 `usercred` builtin |
| `packages/core/src/builtin/usercred.ts`(新) | 个人凭证数据面(set/list/delete,本人 owner 圈定) |
| `packages/core/src/builtin/index.ts` | 装配/导出新模块 |
| `packages/core/src/builtin/secret.ts` | admin list 过滤 `usercred:` 前缀 |
| 节点 config 类型(McpConfig 等) | 加 `credentialDomain?: string` + `allowUserCredential?: boolean` |
| `packages/dashboard/src/pages/...`(新) | 「我的凭证」页 |

(注意:owner 维度免除了 rotate 迁移,`feishuLogin.ts` 无需改动。)

## 测试点

- per-owner 命中个人凭证 → 上游头用个人 token;缺失(或节点无 domain)→ 回落 authRef 默认。
- 数据面:A 的 SK 读不到 / 写不了 B 的 `usercred`(owner 取自 ctx,非入参);value 永不回显。
- `system/secret` 的 admin list 不含 `usercred:` 项(命名空间守卫 + list 过滤)。
- 重新登录换 keyId 后个人凭证仍命中(owner 不变,无需迁移)。
- 会话缓存:个人 token 与管理员 token 分桶,不复用彼此会话。
- 未标 `allowUserCredential` 的节点不出现在 Dashboard 可填列表。

## 分期建议

1. **P1(打通核心)**:`usercred` 存储 + `mcp.ts` per-owner 回落 + 会话分桶 + 数据面端点 +
   secret list 过滤 + bootstrap 建节点。凭 CLI/API 写入验证云效按人落地。
2. **P2(体验)**:节点 `credentialDomain` + `allowUserCredential` 标记 + Dashboard「我的凭证」页。
3. **可选**:个人凭证 TTL / 到期提醒;`http` 节点(`createHttpProvider`)同款支持。
