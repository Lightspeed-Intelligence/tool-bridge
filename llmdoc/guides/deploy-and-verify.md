# Cloudflare 初始化、部署与验收

Cloudflare 是一种宿主，不是业务真源。仓库中的 `packages/gateway/wrangler.jsonc` 必须保持账户中立：不提交 account ID、域名、KV/D1/R2 ID 或环境凭据。

## 推荐入口

从源码 checkout 运行：

```bash
tb init cloudflare --repo .
```

向导负责生成 Admin SK、配置 secrets、创建资源、部署并做基础验证。非交互环境可显式传入 `--account-id`、`--domain` 与 `--yes`；完整选项以 `tb init cloudflare --help` 为准。

手工流程只用于调试：

```bash
pnpm provision
pnpm verify
pnpm turbo run build
pnpm --filter @tool-bridge/dashboard build
pnpm --filter @tool-bridge/gateway run deploy
```

### Lightspeed fork 手工部署细节

fork 侧的一键手工部署入口是 `pnpm deploy:all`:

```sh
pnpm deploy:all
```

= `node scripts/provision.mjs`(幂等建 KV/R2,存在即跳过)+ `pnpm --filter @tool-bridge/dashboard build`(gateway 部署前须先产出 dashboard dist)+ `pnpm --filter @tool-bridge/gateway run deploy`(wrangler deploy)。

**部署前置检查**:部署工作区必须与 `origin/main` 零差异(`git fetch && git diff origin/main --stat` 为空、`git status` 干净)——主 checkout 可能残留他人/往轮 WIP,直接部署会把未提交改动带上线。从干净 worktree 部署时把主 checkout 的 `.env` 拷过去即可(gitignored;provision/deploy 脚本读仓库根 `.env`)。

预期(资源已存在时):

```
provisioning with prefix 'tb' (account 0cb9…)
KV namespace 'tb-kv' exists (id=d18c93de…) — skip
R2 bucket 'tb-r2' exists — skip
provision done.
…
Deployed tb-gateway triggers (…)
  https://tool-bridge.fantacy.live (custom domain)
Current Version ID: …
```

**首次建 KV 时**:provision 会提示把新 id 回填 `packages/gateway/wrangler.jsonc` 的 `TB_KV.id`(当前 id 已回填,日常无需动)。

**先确认部署状态,再决定是否手工部署**:fork 项目在仓库外配置了 Cloudflare Git 集成,推送 `main` 后可能已经自动生成并部署新 Worker version;仓库 `.github/workflows/` 没有 deploy workflow。先读平台状态:

```sh
pnpm --filter @tool-bridge/gateway exec wrangler deployments list --json
pnpm --filter @tool-bridge/gateway exec wrangler versions list --json
```

### 手工探活:curl

```sh
curl -s https://tool-bridge.fantacy.live/healthz
# → {"healthy":true,"version":"<gateway-version>"}
curl -s -H "Authorization: Bearer $TB_SK" -H 'Accept: text/plain' \
  https://tool-bridge.fantacy.live/~help | head -1
# → htbp 0.1
```

`/healthz.version` 是 **Gateway 运行时版本**,不能用来判断 Dashboard npm 包或 `/ui` Static Assets 的版本。

### Dashboard 静态产物验收(本轮含前端时)

静态前端以产物身份为准:比较同一提交本地构建与生产入口 HTML 的 SHA-256,再检查入口引用的 hash chunk 和 SPA 深链接回退。macOS 示例:

```sh
pnpm --filter @tool-bridge/dashboard build
shasum -a 256 packages/dashboard/dist/index.html
curl --retry 3 --retry-all-errors -fsS "$TB_BASE_URL/ui/" | shasum -a 256
curl --retry 3 --retry-all-errors -fsS "$TB_BASE_URL/ui/system/status" | shasum -a 256
rg -o 'assets/[A-Za-z0-9._-]+\.(js|css)' packages/dashboard/dist/index.html | sort -u
```

前两个线上 HTML hash 应与本地入口一致;随后逐个请求列出的 `/ui/assets/<hash-name>` 并确认 200。Dashboard npm 发布与生产 `/ui` 上线是两个独立发布面:前者查 Actions + npm dist-tag,后者查 Worker deployment/version + 本步骤的产物证据。详见 [npm-publish.md](npm-publish.md)。

`provision` 从环境读取账户与命名前缀，幂等创建 KV、R2、D1，并把本地 checkout 的部署目标写入 wrangler 配置。该写回含环境标识，不应作为通用模板提交。

## 必需安全配置

- 首次引导必须预置 `TB_BOOTSTRAP_ADMIN_SK`，并保存在密码管理器；不得从日志回收最高权限凭据。
- SecretStore 的加密密钥必须通过 Wrangler secret 注入，不进入 `vars` 或仓库文件。
- 上游默认只允许 HTTPS；`TB_ALLOW_INSECURE_HTTP=true` 仅供本地验证。
- 自定义域名、canonical origin 与 OAuth redirect 必须一致；未配置域名时使用 workers.dev/preview 入口。

## 验收层次

1. 本地：`pnpm verify`，以及发布/打包相关改动的全仓 build。
2. 部署产物：确认 Worker 与 Dashboard 实际加载的是本轮构建，而非旧 `dist`。
3. 基础 smoke：健康检查、Admin SK 鉴权、受限 SK 的 allow/deny/404 语义。
4. 按需真实验证：MCP、search、device、plugin 等脚本必须显式提供 URL 与 SK。

真实云资源和上游会产生费用或副作用；每轮最多执行一次，需获得用户授权并把证据留在 PR/CI，而不是写入 `current-state.md`。

上游主线视角:项目当前没有正式生产环境。共享开发部署可重置，不承担旧预览状态兼容责任。

## Lightspeed fork smoke 与 CLI 验证

<!-- TODO(sync): fork 已在 fantacy.live 运行生产入口,与上游"无正式生产环境"口径不同;下列 smoke/CLI 步骤为 fork 实际验收流程,人工复核生产口径。 -->

### smoke:线上冒烟

```sh
TB_BASE_URL=https://tool-bridge.fantacy.live pnpm smoke
# → smoke passed against https://tool-bridge.fantacy.live
```

### CLI 验证:`tb status --json`

```sh
pnpm --filter @tool-bridge/cli build   # 首次或改动 CLI 后
node packages/cli/dist/index.js status --json
```

预期:输出可解析 JSON,含 healthy/version(`TB_BASE_URL` 从环境读取)。

## 排错

- **wrangler 报多账户歧义**(`More than one account available`):wrangler OAuth 下有 DJJ 与 Lightspeed 两账户,必须显式指定——`wrangler.jsonc` 已写死 `account_id`,脚本走 `CLOUDFLARE_ACCOUNT_ID`;若单独手敲 wrangler 命令,补 `CLOUDFLARE_ACCOUNT_ID=… npx wrangler …`。
- **custom domain 刚部署后 curl 404/522**:custom domain 首次绑定或 DNS 变更有分钟级生效延迟,等 1-2 分钟重试;也可先用 wrangler deploy 输出里的 workers.dev 地址确认 Worker 本身健康,再等域名。
- **smoke 报 `missing base URL`**:忘了传 `TB_BASE_URL`(它不读 .env),见上方 smoke 步骤。
- **verify 里集成测试起不来 workerd**:确认 `pnpm install` 后再跑;`@cloudflare/vitest-pool-workers` 用 miniflare 本地实例,不需要真实 KV id。
- **`SSL_ERROR_SYSCALL` / `Network connection lost` 等瞬时网络错误**:只对原来的只读查询或幂等 push 重试,随后重新读取远端 refs、Actions、npm dist-tag、Cloudflare deployment/version 与产物 hash;不要未经证据改认证、重打 tag 或重复 deploy。
