/**
 * Bytebase 自托管 MCP 的 plugin(内置源码文件夹,binding 直挂或自部署)。
 *
 * 解决的问题:Bytebase `/mcp` 只认 OAuth bearer(RFC 9728 + DCR),而它的 DCR 硬编码
 * redirect 白名单只放行 loopback——直挂 `kind:mcp` + 托管 OAuth 须走 `tb tool auth --local`
 * 在本机开浏览器授权,且 access token 1h 过期、refresh token 轮换在多 isolate 并发下会
 * 互相作废。本 plugin 改走**服务账号**:用 SA 的 service_key 按需换发访问令牌(token.ts)
 * 并缓存到快过期前,上游 401 时强制重换发重试一次——对平台侧呈现为永不过期、零人工授权
 * 的工具源。
 *
 * **协议零样板**:健康检查、`/~describe`、`/~help`、envelope 编解码、Bearer 鉴权、
 * `X-TB-Request-Id` 去重、上游凭证解包、错误归一全部由 `@tool-bridge/plugin-sdk` 接管;
 * 本文件只剩 Bytebase 业务(换发、重试、白名单双闸、ToolSpec 转换)。用的是 SDK 的
 * **代理型** export(`proxyTools`):工具表的真源是 Bytebase 上游,只有拿到凭证才能枚举。
 *
 * **凭证边界**(同 feishu/meego):email/service_key 不由 plugin 自持——凭证存平台
 * SecretStore(挂载 config.authRef),每次调用由平台 resolve 后经 `X-TB-Upstream-Auth`
 * (base64url JSON `{"email","service_key"[,"base_url"]}`)传入,SDK 按 credentialFields
 * 解析为 `ctx.credentials`。plugin 无凭证即不可用;同一部署可服务多个实例/账号的挂载
 * (token 与 MCP 会话缓存按 `<baseUrl>|<email>|<key 摘要>` 键控)。
 *
 * **权限边界**:SA 继承自己在 Bytebase 的 IAM 角色——工具能做什么由 Bytebase 侧授权决定,
 * 审计日志记在该 SA 名下(不是真实调用者)。只读用途请只给 SA `sqlEditorReadUser` 之类
 * 角色;写操作面可另外用 `BYTEBASE_ALLOWED_TOOLS` 在 plugin 侧再收一道。
 *
 * env(vars):
 *   PLUGIN_TOKEN            — 平台 pluginToken(secret;未配置时仅要求 Bearer 非空)
 *   BYTEBASE_BASE_URL       — 实例 base URL(vars;凭证内 base_url 优先,二者皆缺 → unavailable)
 *   BYTEBASE_ALLOWED_TOOLS  — 工具白名单(vars,逗号分隔;缺省/空 = 放行上游全部工具)
 */

import { createPlugin, type PluginCallContext, TBError, type ToolSpec } from '@tool-bridge/plugin-sdk'
import {
  type BytebaseMcpConfig,
  type BytebaseTool,
  callTool,
  isUnauthorized,
  listTools,
  MCP_PATH,
} from './bytebaseMcp'
import { accessToken, sessionKey } from './token'

export interface Env {
  BYTEBASE_ALLOWED_TOOLS?: string
  BYTEBASE_BASE_URL?: string
  PLUGIN_TOKEN?: string
}

/** 从 ctx.credentials 取出的 Bytebase 服务账号凭证形状。 */
interface BytebaseCredential {
  /** 实例 base URL;缺省回落 env.BYTEBASE_BASE_URL。 */
  base_url?: string
  email: string
  service_key: string
}

/** 去尾斜杠:base URL 参与缓存键与路径拼接,`https://x/` 与 `https://x` 不得算两个实例。 */
function normalizeBaseUrl(raw: string): string {
  return raw.replace(/\/+$/, '')
}

/**
 * 取 Bytebase 凭证。字段由本 export 的 `credentialFields` 声明,SDK 已按声明解析并校验
 * 必填 —— 这里只处理"整份凭证没配"(挂载少配 authRef,是配置错误不是调用方参数错)。
 */
function credentialOf(ctx: PluginCallContext<Env>): BytebaseCredential {
  const values = ctx.credentials
  if (values === undefined) {
    throw new TBError(
      'unavailable',
      '缺上游凭证:挂载节点须配置 authRef,凭证用 `tb secret set <name>'
      + ' --field email=... --field service_key=...` 写入',
      { retryable: false },
    )
  }
  return {
    email: values.email!,
    service_key: values.service_key!,
    ...(typeof values.base_url === 'string' && values.base_url !== ''
      ? { base_url: normalizeBaseUrl(values.base_url) }
      : {}),
  }
}

/** 实例 base URL:凭证内 base_url 优先(多实例挂载),否则 env;皆缺 → unavailable。 */
function resolveBaseUrl(env: Env, cred: BytebaseCredential): string {
  const fromEnv
    = typeof env.BYTEBASE_BASE_URL === 'string' && env.BYTEBASE_BASE_URL !== ''
      ? normalizeBaseUrl(env.BYTEBASE_BASE_URL)
      : undefined
  const baseUrl = cred.base_url ?? fromEnv
  if (baseUrl === undefined) {
    throw new TBError(
      'unavailable',
      'Bytebase 实例地址未配置:请在凭证 JSON 加 base_url,或给部署配 BYTEBASE_BASE_URL',
      { retryable: false },
    )
  }
  return baseUrl
}

/**
 * Bytebase MCP 当前不发 annotations(实测 3.19.0 的 tools/list 只有 name/description/
 * inputSchema),而 effect 决定平台侧 `~help` 的副作用标记与 destructive 的二次确认
 * ——按已知工具名兜底,未知名不臆测(上游哪天补了 annotations,以 annotations 为准)。
 */
const EFFECT_BY_NAME: Record<string, string> = {
  call_api: 'write', // 通用 API 通道,能读也能写
  get_schema: 'read',
  get_skill: 'read',
  propose_database_change: 'destructive',
  query_database: 'read',
  search_api: 'read',
}

function toSpec(t: BytebaseTool): ToolSpec {
  const spec: ToolSpec = { name: t.name }
  if (t.description !== undefined) spec.description = t.description
  if (t.inputSchema !== undefined) spec.inputSchema = t.inputSchema
  if (t.annotations?.readOnlyHint === true) spec.effect = 'read'
  else if (t.annotations?.destructiveHint === true) spec.effect = 'destructive'
  else if (EFFECT_BY_NAME[t.name] !== undefined) spec.effect = EFFECT_BY_NAME[t.name]
  return spec
}

/** 白名单(vars,逗号分隔);空/缺省 = 放行上游全部工具。 */
function allowFilter(env: Env): (t: { name: string }) => boolean {
  const allowed = (env.BYTEBASE_ALLOWED_TOOLS ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(s => s !== '')
  if (allowed.length === 0) return () => true
  return t => allowed.includes(t.name)
}

async function mcpConfig(
  env: Env,
  cred: BytebaseCredential,
  forceToken = false,
): Promise<BytebaseMcpConfig> {
  const baseUrl = resolveBaseUrl(env, cred)
  const tokenCfg = { baseUrl, email: cred.email, serviceKey: cred.service_key }
  const token = await accessToken(tokenCfg, forceToken)
  // 会话键与令牌缓存键同粒度(含 service_key 摘要):换了 key 即另一条身份链,会话不复用。
  return { url: `${baseUrl}${MCP_PATH}`, sessionKey: await sessionKey(tokenCfg), token }
}

/**
 * 执行 `fn`,上游 401 时强制重换发访问令牌后重试一次。缓存的 token 在余量内也可能已
 * 失效(如 service_key 轮换、SA 被停用),401 是唯一失效信号;重试必须绕过缓存(force)。
 */
async function withTokenRetry<T>(
  ctx: PluginCallContext<Env>,
  fn: (cfg: BytebaseMcpConfig) => Promise<T>,
): Promise<T> {
  const cred = credentialOf(ctx)
  try {
    return await fn(await mcpConfig(ctx.env, cred))
  } catch (err) {
    if (!isUnauthorized(err)) throw err
    return await fn(await mcpConfig(ctx.env, cred, true))
  }
}

/** 工厂形态:测试可起多份;部署用下面的默认实例。 */
export function createBytebasePlugin() {
  const plugin = createPlugin<Env>({ token: env => env.PLUGIN_TOKEN })
  plugin.proxyTools('actions', {
    description: 'Bytebase MCP via service account (auto-refreshed access token, no OAuth login)',
    // Bytebase 服务账号凭证:email/service_key 必填,base_url 可选(缺省回落 env)。
    credentialFields: [
      {
        key: 'email',
        label: 'Service Account Email',
        required: true,
        description: 'Bytebase 服务账号邮箱,形如 <name>@service.bytebase.com',
      },
      {
        key: 'service_key',
        label: 'Service Key',
        required: true,
        secret: true,
        description: 'Bytebase 服务账号 service key(创建/轮换时一次性返回,形如 bbs_xxx)',
      },
      {
        key: 'base_url',
        label: 'Instance Base URL',
        required: false,
        secret: false,
        description: 'Bytebase 实例根地址(如 https://bytebase.example.com);缺省回落部署的 BYTEBASE_BASE_URL',
      },
    ],
    list: async ctx =>
      (await withTokenRetry(ctx, listTools)).filter(allowFilter(ctx.env)).map(toSpec),
    call: async ({ name, args }, ctx) => {
      // 白名单外的工具一律不可调用(不能只在 List 过滤,否则知道名字就能绕过)。
      if (!allowFilter(ctx.env)({ name })) {
        throw new TBError(
          'permission_denied',
          `工具 '${name}' 不在 BYTEBASE_ALLOWED_TOOLS 白名单内`,
          { retryable: false },
        )
      }
      // MCP RPC 业务错误(isError)是正常返回值,原样进 ToolResult。
      return await withTokenRetry(ctx, cfg => callTool(cfg, name, args))
    },
  })
  return plugin
}

export default createBytebasePlugin()
