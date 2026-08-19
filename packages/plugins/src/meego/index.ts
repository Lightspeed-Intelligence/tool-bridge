/**
 * 飞书项目(Meego)plugin(内置源码文件夹,binding 直挂或自部署)。
 *
 * 解决的问题:官方托管 MCP 的操作身份固化在挂载 URL 的 userKey 里(所有评论都显示为
 * 同一个人)。本 plugin 直调 Meego open_api,每次请求带 `X-USER-KEY` 指定**操作人**——
 * 评论/写操作以真实调用者身份落地。
 *
 * **操作人解析**(本 plugin 的核心):挂载节点 providerConfig.userKeys 是
 * `{ <keyId>: <user_key> }` 映射(admin 经 registry 维护,调用方不可自改),平台把它作为
 * CallContext.mountConfig 经 X-TB-Context 传入,SDK 解包后即 `ctx.caller`;每次调用按
 * `ctx.caller.keyId` 查表得操作人。未绑定的 key 一律拒绝(permission_denied)——绝不静默
 * 回落到某个默认身份,那正是要修的病。user_key **不做工具入参**:入参可由任何持 key 者
 * 伪造,mountConfig 不能。
 *
 * **协议零样板**:健康检查、`/~describe`、`/~help`、envelope 编解码、Bearer 鉴权、
 * `X-TB-Request-Id` 去重、上游凭证解包、错误归一全部由 `@tool-bridge/plugin-sdk` 接管;
 * 本文件只剩 Meego 业务(工具表、身份解析、PAT 换发重试、参数校验)。工具表在声明期写死
 * (静态 `tools().register()`),故用非代理型 export。
 *
 * **凭证边界**(同 feishu):plugin_id/plugin_secret 不由 plugin 自持——凭证存平台
 * SecretStore(挂载 config.authRef),每次调用经 `X-TB-Upstream-Auth`(base64url JSON
 * `{"plugin_id","plugin_secret"}`)传入,SDK 按 credentialFields 解析为 `ctx.credentials`;
 * PAT 缓存按 plugin_id 键控(pat.ts)。
 *
 * env(vars):
 *   PLUGIN_TOKEN     — 平台 pluginToken(secret;未配置时仅要求 Bearer 非空)
 *   MEEGO_BASE_URL   — open_api 域名 override(vars,可缺省;私有化部署用)
 */

import type { CallContext } from '@tool-bridge/core'
import { createPlugin, type PluginCallContext, TBError } from '@tool-bridge/plugin-sdk'
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

/** 从 ctx.credentials 取出的 Meego 插件凭证形状。 */
interface MeegoCredential {
  plugin_id: string
  plugin_secret: string
}

/**
 * 取 Meego 凭证。字段由本 export 的 `credentials()` 声明,SDK 已按声明解析并校验必填 ——
 * 这里只处理"整份凭证没配"(挂载少配 authRef,是配置错误不是调用方参数错)。
 */
function credentialOf(ctx: PluginCallContext<Env>): MeegoCredential {
  const values = ctx.credentials
  if (values === undefined) {
    throw new TBError(
      'unavailable',
      '缺上游凭证:挂载节点须配置 authRef,凭证用 `tb secret set <name>'
      + ' --field plugin_id=... --field plugin_secret=...` 写入',
      { retryable: false },
    )
  }
  return { plugin_id: values.plugin_id!, plugin_secret: values.plugin_secret! }
}

/**
 * 按调用方 keyId 从 mountConfig.userKeys 解析操作人 user_key。
 * 未配置/未绑定 → permission_denied,附上自助指引;绝不回落默认身份。
 */
function resolveUserKey(caller: CallContext): string {
  const raw = caller.mountConfig?.userKeys
  const map
    = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : undefined
  const userKey = map?.[caller.keyId]
  if (typeof userKey !== 'string' || userKey === '') {
    throw new TBError(
      'permission_denied',
      `调用方 key '${caller.keyId}' 未绑定 Meego 操作人身份:请管理员在挂载节点 providerConfig.userKeys 增加 {"${caller.keyId}":"<user_key>"}(user_key 可经 query_user 用邮箱反查)`,
      { retryable: false },
    )
  }
  return userKey
}

// ---------- 参数校验(rawInputSchema 不校验入参,业务侧自校) ----------

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

// ---------- PAT 换发 + 失效重试 ----------

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
  ctx: PluginCallContext<Env>,
  userKey: string,
  fn: (cfg: MeegoApiConfig) => Promise<T>,
): Promise<T> {
  const cred = credentialOf(ctx)
  try {
    return await fn(await apiConfig(ctx.env, cred, userKey))
  } catch (err) {
    if (!isMeegoAuthError(err)) throw err
    return await fn(await apiConfig(ctx.env, cred, userKey, true))
  }
}

// ---------- 工具入参 JSON Schema(rawInputSchema:进 ~describe / ~help,本表不校验) ----------

const WORK_ITEM_SCHEMA_PROPS = {
  project_key: { type: 'string', description: '空间 projectKey(如 tipsy chat = 6a4226868b7eed94090347eb)' },
  work_item_type_key: { type: 'string', description: '工作项类型 key(经 meego 官方 MCP list_workitem_types 查;缺陷常见为 issue)' },
  work_item_id: { type: 'number', description: '工作项 id(数字)' },
} as const

export function createMeegoPlugin() {
  const plugin = createPlugin<Env>({ token: env => env.PLUGIN_TOKEN })
  const actions = plugin.tools('actions', {
    description:
      'Feishu Project (Meego) open_api tools; comments land as the CALLER\'s bound user_key, not a fixed mount identity',
  })
  // Meego 插件凭证:plugin_id/plugin_secret 两字段,由平台在挂载时校验齐全。
  actions.credentials([
    {
      key: 'plugin_id',
      label: 'Plugin ID',
      required: true,
      description: '飞书项目插件的 plugin_id(开发者后台「插件详情」页)',
    },
    {
      key: 'plugin_secret',
      label: 'Plugin Secret',
      required: true,
      secret: true,
      description: '飞书项目插件的 plugin_secret,用于换发 plugin_token',
    },
  ])

  actions.register(
    'add_comment',
    {
      description:
        '给工作项添加评论(纯文本)。评论以**调用方绑定的 user_key 身份**落地——谁调用显示谁,不再固定为挂载者。',
      effect: 'destructive',
      rawInputSchema: {
        type: 'object',
        properties: {
          ...WORK_ITEM_SCHEMA_PROPS,
          content: { type: 'string', description: '评论内容(纯文本)' },
        },
        required: ['project_key', 'work_item_type_key', 'work_item_id', 'content'],
      },
    },
    async (args: Record<string, unknown>, ctx) => {
      const userKey = resolveUserKey(ctx.caller)
      return withPatRetry(ctx, userKey, cfg =>
        addComment(cfg, {
          projectKey: str(args, 'project_key'),
          workItemTypeKey: str(args, 'work_item_type_key'),
          workItemId: num(args, 'work_item_id'),
          content: str(args, 'content'),
        }))
    },
  )

  actions.register(
    'list_comments',
    {
      description: '列出工作项的评论(含 operator=评论人 user_key,可验证评论身份)。',
      effect: 'read',
      rawInputSchema: {
        type: 'object',
        properties: {
          ...WORK_ITEM_SCHEMA_PROPS,
          page_num: { type: 'number', description: '页码(1 起)' },
          page_size: { type: 'number', description: '每页条数(默认 50)' },
        },
        required: ['project_key', 'work_item_type_key', 'work_item_id'],
      },
    },
    async (args: Record<string, unknown>, ctx) => {
      const userKey = resolveUserKey(ctx.caller)
      const pageNum = optNum(args, 'page_num')
      const pageSize = optNum(args, 'page_size')
      return withPatRetry(ctx, userKey, cfg =>
        listComments(cfg, {
          projectKey: str(args, 'project_key'),
          workItemTypeKey: str(args, 'work_item_type_key'),
          workItemId: num(args, 'work_item_id'),
          ...(pageNum !== undefined ? { pageNum } : {}),
          ...(pageSize !== undefined ? { pageSize } : {}),
        }))
    },
  )

  actions.register(
    'query_user',
    {
      description:
        '查用户详情(user_key/name_cn/email)。绑定新同学时用邮箱反查 user_key。user_keys 与 emails 至少一项。',
      effect: 'read',
      rawInputSchema: {
        type: 'object',
        properties: {
          user_keys: { type: 'array', items: { type: 'string' }, description: '按 user_key 查' },
          emails: { type: 'array', items: { type: 'string' }, description: '按邮箱查(反查 user_key)' },
        },
      },
    },
    async (args: Record<string, unknown>, ctx) => {
      const userKey = resolveUserKey(ctx.caller)
      const userKeys = strArray(args, 'user_keys')
      const emails = strArray(args, 'emails')
      return withPatRetry(ctx, userKey, cfg =>
        queryUser(cfg, {
          ...(userKeys !== undefined ? { userKeys } : {}),
          ...(emails !== undefined ? { emails } : {}),
        }))
    },
  )

  actions.register(
    'whoami',
    {
      description: '返回当前调用方绑定的 Meego 操作人(user_key + 用户详情);验证"评论会显示为谁"。',
      effect: 'read',
      rawInputSchema: { type: 'object', properties: {} },
    },
    async (_args: Record<string, unknown>, ctx) => {
      const userKey = resolveUserKey(ctx.caller)
      const detail = await withPatRetry(ctx, userKey, cfg => queryUser(cfg, { userKeys: [userKey] }))
      return { key_id: ctx.caller.keyId, user_key: userKey, ...(detail as object) }
    },
  )

  actions.register(
    'filter_work_items',
    {
      description:
        '按条件查工作项(需求/缺陷等)。user_keys 传某人 user_key = 查其名下工作项——open_api 内建全角色并集(经办人/研发/负责人),无需手写 MQL 三路 OR。返回含 work_item_status(状态)。',
      effect: 'read',
      rawInputSchema: {
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
    async (args: Record<string, unknown>, ctx) => {
      const userKey = resolveUserKey(ctx.caller)
      const userKeys = strArray(args, 'user_keys')
      const workItemTypeKeys = strArray(args, 'work_item_type_keys')
      const pageNum = optNum(args, 'page_num')
      const pageSize = optNum(args, 'page_size')
      const workItemName = args.work_item_name
      return withPatRetry(ctx, userKey, cfg =>
        filterWorkItems(cfg, {
          projectKey: str(args, 'project_key'),
          ...(userKeys !== undefined ? { userKeys } : {}),
          ...(workItemTypeKeys !== undefined ? { workItemTypeKeys } : {}),
          ...(typeof workItemName === 'string' && workItemName !== '' ? { workItemName } : {}),
          ...(pageNum !== undefined ? { pageNum } : {}),
          ...(pageSize !== undefined ? { pageSize } : {}),
        }))
    },
  )

  return plugin
}

export default createMeegoPlugin()
