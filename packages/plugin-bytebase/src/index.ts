/**
 * Bytebase 自托管 MCP 的 tool-provider plugin(CF Worker,自部署后注册进 tool-bridge)。
 *
 * 解决的问题:Bytebase `/mcp` 只认 OAuth bearer(RFC 9728 + DCR),而它的 DCR 硬编码
 * redirect 白名单只放行 loopback——直挂 `kind:mcp` + 托管 OAuth 须走 `tb tool auth --local`
 * 在本机开浏览器授权,且 access token 1h 过期、refresh token 轮换在多 isolate 并发下会
 * 互相作废(见 llmdoc/must/current-state.md 2026-07-08 条)。本 plugin 改走**服务账号**:
 * 用 SA 的 service_key 按需换发访问令牌(token.ts)并缓存到快过期前,上游 401 时强制
 * 重换发重试一次——对平台侧呈现为永不过期、零人工授权的工具源。
 *
 * **凭证边界**(同 plugin-feishu/plugin-meego):email/service_key 不由 plugin 自持——凭证存
 * 平台 SecretStore(挂载 config.authRef),每次调用由平台 resolve 后经 `X-TB-Upstream-Auth`
 * (base64url JSON `{"email":"...","service_key":"...","base_url":"..."}`)传入。plugin 无凭证
 * 即不可用:公网可达的 endpoint 即使 PLUGIN_TOKEN 泄漏也拿不到任何 Bytebase 凭证;同一
 * 部署可服务多个实例/账号的挂载(token 与 MCP 会话缓存按 `<baseUrl>|<email>` 键控)。
 *
 * **权限边界**:SA 继承自己在 Bytebase 的 IAM 角色——工具能做什么由 Bytebase 侧授权决定,
 * 审计日志记在该 SA 名下(不是真实调用者)。只读用途请只给 SA `sqlEditorReadUser` 之类
 * 角色;写操作面可另外用 `BYTEBASE_ALLOWED_TOOLS` 在 plugin 侧再收一道。
 *
 * 契约面(tool-provider/v1,与 gateway pluginClient/契约校验对齐):
 *   GET  /healthz     → { healthy: true }
 *   GET  /~describe   → { kind, interfaceVersion }
 *   GET  /~help       → Help DSL / HelpJson(Accept 协商)
 *   POST /            → envelope {"tool":"List|Get|Call","arguments":{...}}
 * envelope 鉴权:`Authorization: Bearer <PLUGIN_TOKEN>`(注册后由平台签发,配进 Worker
 * secret);X-TB-Request-Id 幂等去重(isolate 内存,重放返回首次结果)。
 *
 * env(wrangler secret / vars):
 *   PLUGIN_TOKEN            — 平台 pluginToken(secret;注册前可暂缺,届时仅要求非空)
 *   BYTEBASE_BASE_URL       — Bytebase 实例 base URL(vars;凭证内 base_url 优先,二者皆缺 → unavailable)
 *   BYTEBASE_ALLOWED_TOOLS  — 工具白名单(vars,逗号分隔;缺省/空 = 放行上游全部工具)
 */

import {
  base64urlDecode,
  decodePluginCall,
  HEADER_TB_UPSTREAM_AUTH,
  type HelpModel,
  isTBError,
  negotiate,
  renderHelpDsl,
  renderHelpJson,
  RequestDedupe,
  TBError,
} from '@tool-bridge/core'
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

/** X-TB-Upstream-Auth 解码后的 Bytebase 服务账号凭证形状。 */
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
 * 从 X-TB-Upstream-Auth 取 Bytebase 凭证(base64url JSON {email,service_key,base_url?})。
 * 缺失 → unavailable(挂载少配了 authRef,是配置错误不是调用方参数错);坏形状 → invalid_argument。
 */
function upstreamCredential(req: Request): BytebaseCredential {
  const header = req.headers.get(HEADER_TB_UPSTREAM_AUTH)
  if (header === null || header === '') {
    throw new TBError(
      'unavailable',
      `缺 ${HEADER_TB_UPSTREAM_AUTH}:挂载节点须配置 authRef(Bytebase 凭证 JSON {"email","service_key"[,"base_url"]} 存平台凭证保管)`,
      { retryable: false },
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(base64urlDecode(header)))
  } catch {
    throw new TBError('invalid_argument', `${HEADER_TB_UPSTREAM_AUTH} 非法(须 base64url JSON)`)
  }
  const cred = parsed as Partial<BytebaseCredential>
  if (typeof cred.email !== 'string' || cred.email === '') {
    throw new TBError('invalid_argument', `${HEADER_TB_UPSTREAM_AUTH} 缺 email`)
  }
  if (typeof cred.service_key !== 'string' || cred.service_key === '') {
    throw new TBError('invalid_argument', `${HEADER_TB_UPSTREAM_AUTH} 缺 service_key`)
  }
  return {
    email: cred.email,
    service_key: cred.service_key,
    ...(typeof cred.base_url === 'string' && cred.base_url !== ''
      ? { base_url: normalizeBaseUrl(cred.base_url) }
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
      'Bytebase 实例地址未配置:请在凭证 JSON 加 base_url,或给 Worker 配 BYTEBASE_BASE_URL',
      { retryable: false },
    )
  }
  return baseUrl
}

const KIND = 'tool-provider'
const INTERFACE_VERSION = 'tool-provider/v1'

const dedupe = new RequestDedupe()

// ---------- ToolSpec 转换 ----------

interface ToolSpec {
  description?: string
  effect?: string
  inputSchema?: unknown
  name: string
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
function allowFilter(env: Env): (t: BytebaseTool) => boolean {
  const allowed = (env.BYTEBASE_ALLOWED_TOOLS ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(s => s !== '')
  if (allowed.length === 0) return () => true
  return t => allowed.includes(t.name)
}

// ---------- 方法实现(401 → 强制重换发访问令牌重试一次) ----------

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
  env: Env,
  cred: BytebaseCredential,
  fn: (cfg: BytebaseMcpConfig) => Promise<T>,
): Promise<T> {
  try {
    return await fn(await mcpConfig(env, cred))
  } catch (err) {
    if (!isUnauthorized(err)) throw err
    return await fn(await mcpConfig(env, cred, true))
  }
}

async function visibleTools(env: Env, cred: BytebaseCredential): Promise<BytebaseTool[]> {
  return (await withTokenRetry(env, cred, listTools)).filter(allowFilter(env))
}

async function invoke(
  env: Env,
  cred: BytebaseCredential,
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  switch (tool) {
    case 'List':
      return (await visibleTools(env, cred)).map(toSpec)
    case 'Get': {
      const name = args.name
      if (typeof name !== 'string' || name === '') {
        throw new TBError('invalid_argument', 'field \'name\' must be a non-empty string')
      }
      const found = (await visibleTools(env, cred)).find(t => t.name === name)
      if (found === undefined) throw TBError.notFound(`未知工具:'${name}'`)
      return toSpec(found)
    }
    case 'Call': {
      const name = args.name
      if (typeof name !== 'string' || name === '') {
        throw new TBError('invalid_argument', 'field \'name\' must be a non-empty string')
      }
      // 白名单外的工具一律不可调用(不能只在 List 过滤,否则知道名字就能绕过)。
      if (!allowFilter(env)({ name })) {
        throw new TBError(
          'permission_denied',
          `工具 '${name}' 不在 BYTEBASE_ALLOWED_TOOLS 白名单内`,
          { retryable: false },
        )
      }
      const callArgs
        = typeof args.args === 'object' && args.args !== null
          ? (args.args as Record<string, unknown>)
          : {}
      // MCP RPC 业务错误(isError)是正常返回值,原样进 ToolResult。
      return await withTokenRetry(env, cred, cfg => callTool(cfg, name, callArgs))
    }
    default:
      throw new TBError('invalid_argument', `unknown method '${tool}'(见 ~help)`)
  }
}

// ---------- 元端点 ----------

const HELP: HelpModel = {
  node: {
    path: 'plugin-bytebase',
    kind: 'tool',
    description: 'Bytebase MCP via service account (auto-refreshed access token, no OAuth login)',
  },
  cmds: [
    {
      name: 'List',
      method: 'POST',
      path: '/',
      h: 'List Bytebase MCP tools (filtered by BYTEBASE_ALLOWED_TOOLS)',
      returns: 'ToolSpec[]',
      scope: 'read',
    },
    {
      name: 'Get',
      method: 'POST',
      path: '/',
      h: 'Get one tool spec by name',
      returns: 'ToolSpec',
      scope: 'read',
    },
    {
      name: 'Call',
      method: 'POST',
      path: '/',
      h: 'Call a Bytebase MCP tool as the configured service account',
      returns: 'ToolResult',
      scope: 'call',
    },
  ],
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function errorResponse(err: unknown): Response {
  const tb = isTBError(err)
    ? err
    : new TBError('internal', err instanceof Error ? err.message : String(err))
  return json(tb.toJSON(), tb.httpStatus)
}

async function handleEnvelope(req: Request, env: Env): Promise<Response> {
  // 鉴权:Bearer 非空;配置了 PLUGIN_TOKEN 时还须逐字相等(platform-token 语义)。
  const auth = req.headers.get('authorization') ?? ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : ''
  if (token === '') throw TBError.unauthenticated('missing Bearer token')
  if (env.PLUGIN_TOKEN !== undefined && env.PLUGIN_TOKEN !== '' && token !== env.PLUGIN_TOKEN) {
    throw TBError.unauthenticated('bad plugin token')
  }

  const call = decodePluginCall(await req.text())
  const cred = upstreamCredential(req)
  const requestId = req.headers.get('x-tb-request-id')
  const exec = (): Promise<unknown> => invoke(env, cred, call.tool, call.arguments)
  const result
    = requestId !== null && requestId !== '' ? await dedupe.run(requestId, exec) : await exec()
  return json(result ?? null)
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)
    try {
      if (req.method === 'GET') {
        if (url.pathname === '/healthz') return json({ healthy: true })
        if (url.pathname === '/~describe') {
          return json({ kind: KIND, interfaceVersion: INTERFACE_VERSION })
        }
        if (url.pathname === '/~help') {
          if (negotiate(req.headers.get('accept') ?? undefined) === 'json') {
            return json(renderHelpJson(HELP))
          }
          return new Response(renderHelpDsl(HELP), {
            headers: { 'content-type': 'text/plain; charset=utf-8' },
          })
        }
        throw TBError.notFound(`no such path '${url.pathname}'`)
      }
      if (req.method === 'POST' && url.pathname === '/') return await handleEnvelope(req, env)
      throw TBError.notFound(`no such route ${req.method} '${url.pathname}'`)
    } catch (err) {
      return errorResponse(err)
    }
  },
}
