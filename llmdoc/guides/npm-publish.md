# npm 版本与发布

公开包共有七个：`app`、`cli`、`dashboard`、`gateway`、`plugin-sdk`、`sdk`、`server`。`core` 与 `plugins` 是 private，其代码由公开产物消费或打包。

## 是否 bump

按 public artifact ownership 判断：只提升消费者能感知到契约、依赖约束或发布内容变化的公开包。private 源码变化不会机械地沿依赖图提升所有包；但被 bundle 后改变公开运行时行为，仍属于对应公开包的变化。

仓库处于 `0.x`：破坏性变化和新增能力升 minor，纯修复升 patch。隐藏 flag 删除、既有配置从接受改为拒绝、默认安全行为收紧，都属于消费者可感知变化。

## 发布顺序

1. 修改 `packages/<pkg>/package.json` 的 version，并同步 lockfile。
2. 重建该包，直接检查生成入口确实包含新版本；已有 `dist` 不是证据。
3. 执行 `pnpm verify` 和 `pnpm turbo run build`。
4. 用 `scripts/pack-and-verify-package.mjs` 生成并验收最终将发布的确切 tarball。
5. PR 合入 `main` 后才创建 `<pkg>-v<version>` tag。
6. 一次只推一个 tag，等待对应 workflow；不要批量 push tags。
7. 用 `npm view <pkg> version` 或 `npm view <pkg> time.created` 确认 registry 元数据，再下载 registry 中的精确版本 tarball，重复干净安装与烟测。元数据存在不能代替 tarball 可安装性验证。

tag 前缀与目录同名，包括 `plugin-sdk-`。Dashboard 若嵌入 server/gateway 产物，应先发布它依赖的包，再发布承载最终产物的包。

## 打包检查

- 所有公开包统一用 `node scripts/pack-and-verify-package.mjs packages/<pkg> --output-dir <dir>` 打包和验证；CLI 额外传 `--bin tb`。
- 默认模式通过 `pnpm pack` 生成确切 tarball、扫描 packed manifest，并在仓库外创建干净 npm 消费者安装；CLI 还执行 `tb --version` 与 `tb --help`。
- `files`、exports、bin、types 与 `publishConfig` 必须指向构建后真实存在的文件。
- 解包最终 packed tarball，检查其中 `package.json` 的 `dependencies`、`optionalDependencies` 与 `peerDependencies`；不得残留 `catalog:`、`workspace:` 或其他 npm 不支持的工作区协议。
- CI 在全仓 build 后复用同一脚本并传 `--skip-install`，只保留 packed manifest 协议闸门；合入前的 workspace 依赖版本可能尚未发布到 registry，不能把这类不可安装误判为 tarball 协议错误。publish workflow 不得跳过干净安装。
- publish workflow 必须捕获脚本返回的 tarball 路径，并将同一个文件交给 `npm publish`；校验后重新打包会留下产物漂移窗口。
- 声明文件可能跨包引用私有源码，不能只依赖 monorepo typecheck。
- 版本字符串若编译进产物，必须在 bump 后重建并搜索实际入口。
- 发布失败时修复后重建、重验；不要复用已经推送且不可回收的 npm 版本。

不要在 llmdoc 记录某次发布的 latest、digest 或传播耗时;这些属于 registry、tag 与 CI 证据。

## Lightspeed fork 发布操作(实测)

   **多包同发必须逐个 push tag**:`git push origin tag1 tag2 tag3` 一次推多个 tag 时 GitHub **不触发任何 tag workflow**(2026-07-08 实测:四 tag 同推零触发;删除远端 tag 后逐个重推,四个 workflow 全部正常触发)。tag 已推但没触发时的恢复手法:`git push origin :refs/tags/<tag>` 删远端 → 单独重推。

3. CI 自动发布(`.github/workflows/publish-<pkg>.yml`,五包各一份,也可 workflow_dispatch 手动触发):
   - 校验 tag 版本与 package.json 版本一致(不一致直接 fail,防漂移);
   - typecheck / test / build(`publish-server.yml` 额外做 **dist 起服冒烟**:从构建产物直接起进程探活,防"测试绿但发布物起不来");
   - `npm publish` 走 **npm Trusted Publishing(OIDC,免 token)**。workflow 里先 `npm install -g npm@11`(OIDC 发布需 npm >= 11.5.1,setup-node 自带的可能偏旧;**不要用 `npm@latest`**,见坑)。
4. 验证:`npm view @tool-bridge/<pkg> version`。

### Dashboard 有两个独立发布面

- `dashboard-v<版本>` 触发 `publish-dashboard.yml`,只证明 `@tool-bridge/dashboard` 已发布到 npm;证据是 Actions run 成功 + `npm view @tool-bridge/dashboard dist-tags.latest` 命中目标版本。
- 生产 `https://tool-bridge.fantacy.live/ui/` 是 Gateway Worker 的 Static Assets,不从 npm dist-tag 自动更新;它随承载 Gateway 的部署流水线生效。当前项目在仓库外配置 Cloudflare Git 集成,`main` 推送后可能已经自动部署,仓库内没有对应 deploy workflow。
- 因此 Dashboard 发版必须分别报告「Dashboard npm 版本」与「生产 Worker version + `/ui` 产物身份」。`/healthz.version` 属于 Gateway 运行时,不能用来判断 Dashboard npm/静态资产版本。生产侧的部署去重、HTML/chunk hash 与 smoke 验收见 [deploy-and-verify.md](deploy-and-verify.md)。

## 新增可发布包首发(两段式)

Trusted Publisher 必须在包已存在后才能配置,所以新包固定走两段:

1. **手动首发**:`npm publish --dry-run` 核对 tarball 内容后,由**用户亲自**执行 `npm publish`(不要由 agent 跑,见坑 1)。
2. **配置 Trusted Publisher**:用户在 npmjs.com 该包设置页 → Trusted Publisher → GitHub Actions,填 repo `TokenRollAI/tool-bridge` + 对应 workflow 文件名(如 `publish-sdk.yml`)。
3. 之后按上节 tag 触发 CI 发布。

当前待走此流程:server 0.1.0(workflow `publish-server.yml`)。其余四包均已走完。**顺序约束:dashboard 须先于 server 存在于 registry**——dashboard 是 server 的 regular dependency(dashboard 0.2.0 已发布,约束已满足)。

## 坑

- **agent 跑 `npm publish` 会卡死在 2FA/EOTP**:npm 触发浏览器一次性认证,认证 URL 在 agent 命令输出中被脱敏(显示 `***`),放后台等也没用。二选一:让用户在会话里 `! cd packages/xxx && npm publish` 自己跑(URL 直接显示给用户);或用户提供 TOTP,agent 走 `npm publish --otp=<code>`。
- **CI 发布 E422:provenance 校验要求 `repository.url`**:Trusted Publishing 会签 provenance,npm registry 校验 package.json 的 `repository.url` 必须匹配 `https://github.com/TokenRollAI/tool-bridge`,缺失或不匹配直接拒绝(`cli-v0.1.1` 实测被拒:`"repository.url" is ""`;补 `repository` 字段后同 tag 重跑成功)。可发布包的 package.json 必须带 `repository` 字段(含 `directory` 指向包目录)。手动发布无 provenance,不受影响——所以首发成功不代表 CI 能发。
- **发布前先 `npm publish --dry-run`**:核对 tarball 只含 dist/LICENSE/README/package.json,且 unpacked size 合理(bundle 漏配 noExternal 时体积会异常)。
- **`npm install -g npm@latest` 会引入上游破坏**:npm 12.0.0(2026-07-08 发布)的 `npm publish` 走 provenance 路径时 `Cannot find module 'sigstore'` 直接崩(cli-v0.6.0 两次实测,重跑无效)。五个 publish workflow 已钉 `npm@11`;后续升 major 前先确认 publish 路径可用。
- **git push 偶发 `SSL_ERROR_SYSCALL`**:网络抖动,直接重试,不要误判为凭据问题去改配置。
