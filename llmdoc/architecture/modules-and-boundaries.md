# 模块与边界

## 依赖方向

```text
core
  ↑
app ← plugins
  ↑       ↑
gateway  plugin-sdk
server
sdk

CLI / Dashboard ──HTTP──> app contract
```

`core` 与 `plugins` 是 private workspace 包；其余 app、cli、dashboard、gateway、plugin-sdk、sdk、server 是 public artifact。发布判断按 artifact ownership，不沿源码依赖图机械 bump。

## 模块 → core / 宿主落点

<!-- TODO(sync): 上游已把宿主中立业务从 gateway 抽到 `packages/app`(createTbApp/TbAppDeps 现在在 app,gateway 降为 Workers adapter);下表沿用 fork 视角的 gateway 落点标注,需人工按新 app/gateway 边界订正落点列。fork 定制模块(plugin-feishu/meego/bytebase)保留。 -->

| 模块 | 职责 | core 落点 | 宿主落点 |
|---|---|---|---|
| HTBP Tree(核心枢纽) | 节点注册表、路由、`~help`/`~skill`/`~tree`/`~describe`、内容协商、调用分发 | `tree/` + `htbp/` | app `tbApp.ts`(宿主中立 createTbApp)+ gateway `kvStateStore.ts` |
| Tool Layer | mcp/http/builtin Provider 聚合与调用代理、虚拟化、remote 联邦 | `tool/` | gateway `providers/mcp|http|remote|toolCache` |
| Context Layer | 多来源上下文统一读写检索面(四动词 + Search + `$ref`) | `context/` | gateway `providers/r2Object|s3Object|s3Sign` + `refToken.ts` |
| Skillhub Layer | Agent Skill 仓库(每 skill = `<id>/SKILL.md` + 文本文件;List/Get/Search/Publish/Remove) | `skillhub/`(frontmatter 解析 + provider,复用 context 的 ObjectStore/objectProvider) | 复用 context 的 gateway providers(r2/s3);网关 `tbApp.ts` 装配 `skillhubProviderFor` 落 `skills/<path>` 前缀 |
| Device Gateway | 设备 WS 反向注册 + 调用转发 | `device/`(帧/状态机/shell 白名单/设备侧 client) | **协议行为单一真源:gateway `deviceHello.ts`(processDeviceHello,宿主中立)**;两个宿主胶水:gateway `deviceSession.ts`(DO,WS hibernation)与 server `deviceHub.ts`(Node ws);cli `deviceRuntime.ts`;core `node/`(FsObjectStore/shellExecutor) |
| Auth(横切) | SK 签发/作用域/访问判定/SecretStore | `auth/` + `secret/` | gateway 认证中间件;SK 哈希与密文存 StateStore |
| builtin 管理面 | `system/*` 七模块:sk / secret / registry / status / plugin / federation / annotation | `builtin/` | 经 gateway dispatch |
| Agent 反馈 | `~feedback` 保留段(per-path 一级协议能力,非 builtin):提交/投票/下钻,头部条目注入 ~help | core `feedback/` 存储 + gateway `tbApp.ts` 路由 | 权限判定落目标 path |
| SDK | 内嵌 TB 实例 / 程序化注册 / 反向连接 | —(装配层) | `packages/sdk`:createToolBridge = core + gateway 的 createTbApp + 内存宿主缺省 |
| CLI | 纯 API 客户端 `tb`,18 个子命令一一映射接口面,**无专用端点** | — | `packages/cli`(commander;npm 发布物) |
| Plugin System | 自定义 Provider 注册与生命周期(探活/契约校验/信封传输) | `plugin/` | gateway `providers/pluginClient|pluginTool|pluginContext` + builtin `system/plugin`;in-repo plugin 参考实现:`packages/plugin-feishu`(飞书 TAT 自动换发)、`packages/plugin-meego`(每调用者身份)、`packages/plugin-bytebase`(Bytebase SA 令牌自动换发,免 OAuth 人工授权),均为 CF Worker |
| Dashboard | `~help` 通用渲染器 + 管理表单,**无专用后端** | — | `packages/dashboard`(React SPA)经 gateway Static Assets 挂 `/ui` |
| 部署 | CF 与 Docker 两条路径产出同一棵树 | — | CF:`scripts/provision.mjs` + wrangler;Docker/Node:`packages/server`(SQLite/FS/ws DeviceHub)+ 根 Dockerfile,见 [../guides/docker-host.md](../guides/docker-host.md) |

## 包职责

| 包 | 职责 | 不应承担 |
|---|---|---|
| `core` | 类型、授权、树、store、builtin 纯逻辑、plugin/search 协议 | 网络、环境变量、运行时资源 |
| `app` | Hono 路由、发现/调用、provider 编排、宿主注入面 | Wrangler、SQLite、Node/CF 专属启动 |
| `gateway` | Workers Env → app 依赖，KV/R2/D1/DO/Assets | 复制 app 业务分支 |
| `server` | Node 配置、SQLite/FS/ws、HTTP 监听、Docker 入口 | 改写共享协议语义 |
| `sdk` | 嵌入 app、注册本地 provider、反向连接 | 暴露尚未实现的网关侧设备宿主 API |
| `plugin-sdk` | plugin descriptor、OperationRegistry、envelope、受控出站 | 承担平台注册和 SecretStore |
| `plugins` | 内置 provider 源码、生成 catalog、迁移回归闸门 | 运行时注册状态 |
| `cli` | 严格 argv、本地语义、HTTP 调用、脚本输出 | 成为服务端唯一校验层 |
| `dashboard` | 同一 HTTP 契约的交互界面 | import core 形成浏览器/服务端耦合 |

## app 宿主注入

`TbAppDeps` 的基础注入点是：

- `state: StateStore`
- `objects?: () => ObjectStore`
- `secrets: SecretStoreImpl`
- `device?: DeviceChannel`
- `search?: SearchIndex`

另有 assets、remote、plugin catalog/bindings、本地 provider 与缓存/安全配置。`DeviceChannel` 是 app 当前消费的真实接口；不要再把未实现的 SDK `DeviceTransport` 当成现状。

## 当前节点与 builtin

节点 kind 的唯一清单在 `packages/core/src/types.ts` 的 `NODE_KINDS`：directory、mcp、http、builtin、context、device、remote、tool、skillhub。

bootstrap builtin 清单在 `packages/app/src/bootstrap.ts` 的 `BUILTIN_MODULES`：sk、secret、registry、status、plugin、catalog、federation、annotation。`~feedback` 是保留端点，不是 builtin 模块。

## 运行时差异

- Workers StateStore 基于 KV，认证和注册读存在最终一致窗口；Node SQLite 强一致。
- Workers 设备会话结果与连接元数据进入 DO storage；Node 部分幂等结果只在进程内。
- Workers 静态 UI 经 Assets binding；Node 从 `TB_UI_DIR` 或 dashboard 包读取。
- 共享逻辑必须留在 core/app；适配器差异写成注入实现和明确测试，不在业务路由分叉。
