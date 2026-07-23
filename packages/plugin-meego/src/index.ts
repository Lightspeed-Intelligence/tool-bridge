/**
 * 飞书项目(Meego)tool-provider plugin(CF Worker,自部署后注册进 tool-bridge)。
 *
 * 解决的问题:官方托管 MCP 的操作身份固化在挂载 URL 的 userKey 里(所有评论都显示为
 * 同一个人)。本 plugin 直调 Meego open_api,每次请求带 `X-USER-KEY` 指定**操作人**——
 * 评论/写操作以真实调用者身份落地。
 *
 * **操作人解析**(本 plugin 的核心):挂载节点 config.providerConfig.userKeys 是
 * `{ <keyId>: <user_key> }` 映射(admin 经 registry 维护,调用方不可自改),网关把它作为
 * CallContext.mountConfig 经 X-TB-Context 传入;每次调用按 ctx.keyId 查表得操作人。
 * 未绑定的 key 一律拒绝(permission_denied)——绝不静默回落到某个默认身份,那正是
 * 要修的病。user_key **不做工具入参**:入参可由任何持 key 者伪造,mountConfig 不能。
 *
 * **凭证边界**(同 plugin-feishu):plugin_id/plugin_secret 不由 plugin 自持——凭证存平台
 * SecretStore(挂载 config.authRef),每次调用经 `X-TB-Upstream-Auth`(base64url JSON
 * `{"plugin_id":"...","plugin_secret":"..."}`)传入;PAT 缓存按 plugin_id 键控(pat.ts)。
 *
 * 契约面(tool-provider/v1,与 gateway pluginClient/契约校验对齐):
 *   GET  /healthz     → { healthy: true }
 *   GET  /~describe   → { kind, interfaceVersion }
 *   GET  /~help       → Help DSL / HelpJson(Accept 协商)
 *   POST /            → envelope {"tool":"List|Get|Call","arguments":{...}}
 * envelope 鉴权:`Authorization: Bearer <PLUGIN_TOKEN>`;X-TB-Request-Id 幂等去重。
 *
 * env(wrangler secret / vars):
 *   PLUGIN_TOKEN     — 平台 pluginToken(secret;注册后配进 Worker secret)
 *   MEEGO_BASE_URL   — open_api 域名 override(vars,可缺省;私有化部署用)
 */

import {
  base64urlDecode,
  type CallContext,
  decodeCallContext,
  decodePluginCall,
  HEADER_TB_CONTEXT,
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
  addComment,
  filterWorkItems,
  isMeegoAuthError,
  listComments,
  type MeegoApiConfig,
  queryUser,
} from './meegoApi'
import { DEFAULT_BASE_URL, pluginAccessToken } from './pat'

export interface Env {
  MEEGO_BASE_URL?: string
  PLUGIN_TOKEN?: string
}

/** X-TB-Upstream-Auth 解码后的 Meego 插件凭证形状。 */
interface MeegoCredential {
  plugin_id: string
  plugin_secret: string
}

function upstreamCredential(req: Request): MeegoCredential {
  const header = req.headers.get(HEADER_TB_UPSTREAM_AUTH)
  if (header === null || header === '') {
    throw new TBError(
      'unavailable',
      `缺 ${HEADER_TB_UPSTREAM_AUTH}:挂载节点须配置 authRef(Meego 凭证 JSON {"plugin_id","plugin_secret"} 存平台凭证保管)`,
      { retryable: false },
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(base64urlDecode(header)))
  } catch {
    throw new TBError('invalid_argument', `${HEADER_TB_UPSTREAM_AUTH} 非法(须 base64url JSON)`)
  }
  const cred = parsed as Partial<MeegoCredential>
  if (typeof cred.plugin_id !== 'string' || cred.plugin_id === '') {
    throw new TBError('invalid_argument', `${HEADER_TB_UPSTREAM_AUTH} 缺 plugin_id`)
  }
  if (typeof cred.plugin_secret !== 'string' || cred.plugin_secret === '') {
    throw new TBError('invalid_argument', `${HEADER_TB_UPSTREAM_AUTH} 缺 plugin_secret`)
  }
  return { plugin_id: cred.plugin_id, plugin_secret: cred.plugin_secret }
}

/**
 * 按调用方 keyId 从 mountConfig.userKeys 解析操作人 user_key。
 * 未配置/未绑定 → permission_denied,附上自助指引;绝不回落默认身份。
 */
function resolveUserKey(ctx: CallContext): string {
  const raw = ctx.mountConfig?.userKeys
  const map
    = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : undefined
  const userKey = map?.[ctx.keyId]
  if (typeof userKey !== 'string' || userKey === '') {
    throw new TBError(
      'permission_denied',
      `调用方 key '${ctx.keyId}' 未绑定 Meego 操作人身份:请管理员在挂载节点 providerConfig.userKeys 增加 {"${ctx.keyId}":"<user_key>"}(user_key 可经 query_user 用邮箱反查)`,
      { retryable: false },
    )
  }
  return userKey
}

const KIND = 'tool-provider'
const INTERFACE_VERSION = 'tool-provider/v1'

const dedupe = new RequestDedupe()

// ---------- 工具表 ----------

interface ToolSpec {
  description?: string
  effect?: string
  inputSchema?: unknown
  name: string
}

const WORK_ITEM_SCHEMA_PROPS = {
  project_key: { type: 'string', description: '空间 projectKey(如 tipsy chat = 6a4226868b7eed94090347eb)' },
  work_item_type_key: { type: 'string', description: '工作项类型 key(经 meego 官方 MCP list_workitem_types 查;缺陷常见为 issue)' },
  work_item_id: { type: 'number', description: '工作项 id(数字)' },
} as const

const TOOLS: ToolSpec[] = [
  {
    name: 'add_comment',
    description:
      '给工作项添加评论(纯文本)。评论以**调用方绑定的 user_key 身份**落地——谁调用显示谁,不再固定为挂载者。',
    effect: 'destructive',
    inputSchema: {
      type: 'object',
      properties: {
        ...WORK_ITEM_SCHEMA_PROPS,
        content: { type: 'string', description: '评论内容(纯文本)' },
      },
      required: ['project_key', 'work_item_type_key', 'work_item_id', 'content'],
    },
  },
  {
    name: 'list_comments',
    description: '列出工作项的评论(含 operator=评论人 user_key,可验证评论身份)。',
    effect: 'read',
    inputSchema: {
      type: 'object',
      properties: {
        ...WORK_ITEM_SCHEMA_PROPS,
        page_num: { type: 'number', description: '页码(1 起)' },
        page_size: { type: 'number', description: '每页条数(默认 50)' },
      },
      required: ['project_key', 'work_item_type_key', 'work_item_id'],
    },
  },
  {
    name: 'query_user',
    description:
      '查用户详情(user_key/name_cn/email)。绑定新同学时用邮箱反查 user_key。user_keys 与 emails 至少一项。',
    effect: 'read',
    inputSchema: {
      type: 'object',
      properties: {
        user_keys: { type: 'array', items: { type: 'string' }, description: '按 user_key 查' },
        emails: { type: 'array', items: { type: 'string' }, description: '按邮箱查(反查 user_key)' },
      },
    },
  },
  {
    name: 'whoami',
    description: '返回当前调用方绑定的 Meego 操作人(user_key + 用户详情);验证"评论会显示为谁"。',
    effect: 'read',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'filter_work_items',
    description:
      '按条件查工作项(需求/缺陷等)。user_keys 传某人 user_key = 查其名下工作项——open_api 内建全角色并集(经办人/研发/负责人),无需手写 MQL 三路 OR。返回含 work_item_status(状态)。',
    effect: 'read',
    inputSchema: {
      type: 'object',
      properties: {
        project_key: {
          type: 'string',
          description: '空间 projectKey(如 tipsy chat = 6a4226868b7eed94090347eb)',
        },
        work_item_type_keys: {
          type: 'array',
          items: { type: 'string' },
          description: '工作项类型 key(缺陷=issue,需求=story;可多选)',
        },
        user_keys: {
          type: 'array',
          items: { type: 'string' },
          description: '按人筛(该用户名下全角色);查"我名下"传自己 user_key(见 whoami)',
        },
        work_item_name: { type: 'string', description: '按名称模糊筛' },
        page_num: { type: 'number', description: '页码(1 起)' },
        page_size: { type: 'number', description: '每页条数(默认 50)' },
      },
      required: ['project_key'],
    },
  },
]

// ---------- 参数校验 ----------

function str(args: Record<string, unknown>, field: string): string {
  const v = args[field]
  if (typeof v !== 'string' || v === '') {
    throw new TBError('invalid_argument', `field '${field}' must be a non-empty string`)
  }
  return v
}

function num(args: Record<string, unknown>, field: string): number {
  const v = args[field]
  // 允许数字字符串:MQL 查回来的 work_item_id 常以字符串形态出现在上下文里。
  const n = typeof v === 'string' && v !== '' ? Number(v) : v
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    throw new TBError('invalid_argument', `field '${field}' must be a number`)
  }
  return n
}

function optNum(args: Record<string, unknown>, field: string): number | undefined {
  return args[field] === undefined ? undefined : num(args, field)
}

function strArray(args: Record<string, unknown>, field: string): string[] | undefined {
  const v = args[field]
  if (v === undefined) return undefined
  if (!Array.isArray(v) || v.some(x => typeof x !== 'string' || x === '')) {
    throw new TBError('invalid_argument', `field '${field}' must be an array of non-empty strings`)
  }
  return v as string[]
}

// ---------- 方法实现(鉴权失效 → 强制重换发 PAT 重试一次) ----------

async function apiConfig(
  env: Env,
  cred: MeegoCredential,
  userKey: string,
  forcePat = false,
): Promise<MeegoApiConfig> {
  const baseUrl = env.MEEGO_BASE_URL ?? DEFAULT_BASE_URL
  const pat = await pluginAccessToken(
    { pluginId: cred.plugin_id, pluginSecret: cred.plugin_secret, baseUrl },
    forcePat,
  )
  return { baseUrl, pat, userKey }
}

/**
 * 执行 `fn`,鉴权失效时强制重换发 PAT 后重试一次。缓存的 PAT 在余量内也可能已被
 * 吊销(如重置 plugin_secret);重试必须绕过缓存(force)。
 */
async function withPatRetry<T>(
  env: Env,
  cred: MeegoCredential,
  userKey: string,
  fn: (cfg: MeegoApiConfig) => Promise<T>,
): Promise<T> {
  try {
    return await fn(await apiConfig(env, cred, userKey))
  } catch (err) {
    if (!isMeegoAuthError(err)) throw err
    return await fn(await apiConfig(env, cred, userKey, true))
  }
}

async function callTool(
  env: Env,
  cred: MeegoCredential,
  ctx: CallContext,
  name: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  switch (name) {
    case 'add_comment': {
      const userKey = resolveUserKey(ctx)
      return withPatRetry(env, cred, userKey, cfg =>
        addComment(cfg, {
          projectKey: str(args, 'project_key'),
          workItemTypeKey: str(args, 'work_item_type_key'),
          workItemId: num(args, 'work_item_id'),
          content: str(args, 'content'),
        }))
    }
    case 'list_comments': {
      const userKey = resolveUserKey(ctx)
      const pageNum = optNum(args, 'page_num')
      const pageSize = optNum(args, 'page_size')
      return withPatRetry(env, cred, userKey, cfg =>
        listComments(cfg, {
          projectKey: str(args, 'project_key'),
          workItemTypeKey: str(args, 'work_item_type_key'),
          workItemId: num(args, 'work_item_id'),
          ...(pageNum !== undefined ? { pageNum } : {}),
          ...(pageSize !== undefined ? { pageSize } : {}),
        }))
    }
    case 'query_user': {
      const userKey = resolveUserKey(ctx)
      const userKeys = strArray(args, 'user_keys')
      const emails = strArray(args, 'emails')
      return withPatRetry(env, cred, userKey, cfg =>
        queryUser(cfg, {
          ...(userKeys !== undefined ? { userKeys } : {}),
          ...(emails !== undefined ? { emails } : {}),
        }))
    }
    case 'whoami': {
      const userKey = resolveUserKey(ctx)
      const detail = await withPatRetry(env, cred, userKey, cfg =>
        queryUser(cfg, { userKeys: [userKey] }))
      return { key_id: ctx.keyId, user_key: userKey, ...(detail as object) }
    }
    case 'filter_work_items': {
      const userKey = resolveUserKey(ctx)
      const userKeys = strArray(args, 'user_keys')
      const workItemTypeKeys = strArray(args, 'work_item_type_keys')
      const pageNum = optNum(args, 'page_num')
      const pageSize = optNum(args, 'page_size')
      const workItemName = args.work_item_name
      return withPatRetry(env, cred, userKey, cfg =>
        filterWorkItems(cfg, {
          projectKey: str(args, 'project_key'),
          ...(userKeys !== undefined ? { userKeys } : {}),
          ...(workItemTypeKeys !== undefined ? { workItemTypeKeys } : {}),
          ...(typeof workItemName === 'string' && workItemName !== ''
            ? { workItemName }
            : {}),
          ...(pageNum !== undefined ? { pageNum } : {}),
          ...(pageSize !== undefined ? { pageSize } : {}),
        }))
    }
    default:
      throw TBError.notFound(`未知工具:'${name}'`)
  }
}

async function invoke(
  env: Env,
  cred: MeegoCredential,
  ctx: CallContext,
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  switch (tool) {
    case 'List':
      return TOOLS
    case 'Get': {
      const name = args.name
      if (typeof name !== 'string' || name === '') {
        throw new TBError('invalid_argument', 'field \'name\' must be a non-empty string')
      }
      const found = TOOLS.find(t => t.name === name)
      if (found === undefined) throw TBError.notFound(`未知工具:'${name}'`)
      return found
    }
    case 'Call': {
      const name = args.name
      if (typeof name !== 'string' || name === '') {
        throw new TBError('invalid_argument', 'field \'name\' must be a non-empty string')
      }
      const callArgs
        = typeof args.args === 'object' && args.args !== null
          ? (args.args as Record<string, unknown>)
          : {}
      const value = await callTool(env, cred, ctx, name, callArgs)
      return { content: value }
    }
    default:
      throw new TBError('invalid_argument', `unknown method '${tool}'(见 ~help)`)
  }
}

// ---------- 元端点 ----------

const HELP: HelpModel = {
  node: {
    path: 'plugin-meego',
    kind: 'tool',
    description:
      'Feishu Project (Meego) open_api tools; comments land as the CALLER\'s bound user_key, not a fixed mount identity',
  },
  cmds: [
    {
      name: 'List',
      method: 'POST',
      path: '/',
      h: 'List Meego tools (add_comment/list_comments/query_user/whoami)',
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
      h: 'Call a Meego tool as the caller\'s bound identity (providerConfig.userKeys[keyId])',
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
  const ctxHeader = req.headers.get(HEADER_TB_CONTEXT)
  if (ctxHeader === null || ctxHeader === '') {
    throw new TBError('invalid_argument', `缺 ${HEADER_TB_CONTEXT}(操作人身份解析依赖 CallContext)`)
  }
  const ctx = decodeCallContext(ctxHeader)
  const requestId = req.headers.get('x-tb-request-id')
  const exec = (): Promise<unknown> => invoke(env, cred, ctx, call.tool, call.arguments)
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
