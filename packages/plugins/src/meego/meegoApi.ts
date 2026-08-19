/**
 * 飞书项目(Meego)open_api 客户端(纯 fetch,形状对齐官方 project-oapi-sdk-golang v2)。
 *
 * 请求头:`X-PLUGIN-TOKEN`(插件身份,pat.ts 换发)+ `X-USER-KEY`(**操作人身份**,
 * 写操作以此落地为"谁评论/谁创建"——本 plugin 存在的全部意义)。
 *
 * 响应统一形状 `{err_code,err_msg,data,...}`(err_code 0 = 成功);token 失效的信号是
 * HTTP 401 或 err_msg 明示 token 无效/过期——都归一为 `MeegoAuthError` 供调用方强制重换发重试。
 * 其余业务错误(无权限/参数错/不存在)归一 TBError 原样上抛,plugin 不重试。
 */

import { TBError } from '@tool-bridge/core'
import { createGuardedFetch } from '../_runtime/guardedFetch'

// X-PLUGIN-TOKEN / X-USER-KEY 是凭证头,跨源跳转须剥离;换发出的 PAT 不应被 302 送走。
const meegoApiFetch = createGuardedFetch({
  crossOriginRedirect: 'error',
  sensitiveHeaders: ['x-plugin-token', 'x-user-key'],
})

/** 鉴权失效标记:调用方捕获后强制重换发 PAT 重试一次。 */
export class MeegoAuthError extends Error {
  constructor(detail: string) {
    super(detail)
    this.name = 'MeegoAuthError'
  }
}

export function isMeegoAuthError(err: unknown): err is MeegoAuthError {
  return err instanceof MeegoAuthError
}

export interface MeegoApiConfig {
  baseUrl: string
  /** plugin_token(插件身份)。 */
  pat: string
  /** 操作人 user_key;写接口必带(读接口部分也要求)。 */
  userKey: string
}

interface MeegoEnvelope {
  data?: unknown
  err_code?: number
  err_msg?: string
  error?: { code?: number, msg?: string }
  pagination?: unknown
}

/**
 * token 失效判定(触发强制重换发重试):HTTP 401,或 err_msg 明示 token 无效/过期。
 * 官方未公开稳定的鉴权错误码表(Go SDK 也不按码重试),按消息判定比猜错误码保守——
 * 误判为业务错误只是少一次重试,反向误判会把业务错误骗进重试循环。
 */
function isTokenInvalidMsg(msg: string): boolean {
  return /token/i.test(msg) && /(invalid|expire|失效|过期|无效)/i.test(msg)
}

/**
 * 单次 open_api 请求:2xx 且 err_code 0 → 返回整个响应体(data+pagination 由调用方取);
 * 401/鉴权段 err_code → MeegoAuthError;其余按 TBError 归一。
 */
async function request(
  cfg: MeegoApiConfig,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<MeegoEnvelope> {
  let resp: Response
  try {
    resp = await meegoApiFetch(`${cfg.baseUrl}${path}`, {
      method,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'X-PLUGIN-TOKEN': cfg.pat,
        'X-USER-KEY': cfg.userKey,
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
  } catch (err) {
    throw new TBError(
      'unavailable',
      `Meego open_api 网络失败:${err instanceof Error ? err.message : String(err)}`,
      { retryable: true },
    )
  }
  if (resp.status === 401) throw new MeegoAuthError('HTTP 401')
  const parsed = (await resp.json().catch(() => null)) as MeegoEnvelope | null
  if (parsed === null) {
    throw new TBError('unavailable', `Meego open_api 响应非 JSON(HTTP ${resp.status})`, {
      retryable: resp.status >= 500,
    })
  }
  const code = parsed.err_code ?? parsed.error?.code ?? 0
  const msg = parsed.err_msg ?? parsed.error?.msg ?? ''
  if (code !== 0) {
    if (isTokenInvalidMsg(msg)) throw new MeegoAuthError(`err_code=${code} ${msg}`)
    throw new TBError(
      'invalid_argument',
      `Meego open_api 业务错误:err_code=${code} ${msg}(路径 ${path})`.trim(),
    )
  }
  if (!resp.ok) {
    throw new TBError('unavailable', `Meego open_api HTTP ${resp.status}(路径 ${path})`, {
      retryable: resp.status >= 500,
    })
  }
  return parsed
}

// ---------- 评论 ----------

export interface AddCommentArgs {
  content: string
  projectKey: string
  workItemId: number
  workItemTypeKey: string
}

/** POST /open_api/:project_key/work_item/:work_item_type_key/:work_item_id/comment/create → 评论 id。 */
export async function addComment(cfg: MeegoApiConfig, args: AddCommentArgs): Promise<unknown> {
  const path = `/open_api/${encodeURIComponent(args.projectKey)}/work_item/${encodeURIComponent(args.workItemTypeKey)}/${args.workItemId}/comment/create`
  const resp = await request(cfg, 'POST', path, { content: args.content })
  return { comment_id: resp.data }
}

export interface ListCommentsArgs {
  pageNum?: number
  pageSize?: number
  projectKey: string
  workItemId: number
  workItemTypeKey: string
}

/** GET .../comments → 评论列表(含 pagination)。 */
export async function listComments(cfg: MeegoApiConfig, args: ListCommentsArgs): Promise<unknown> {
  const qs = new URLSearchParams()
  if (args.pageNum !== undefined) qs.set('page_num', String(args.pageNum))
  if (args.pageSize !== undefined) qs.set('page_size', String(args.pageSize))
  const qsText = qs.toString()
  const query = qsText === '' ? '' : `?${qsText}`
  const path = `/open_api/${encodeURIComponent(args.projectKey)}/work_item/${encodeURIComponent(args.workItemTypeKey)}/${args.workItemId}/comments${query}`
  const resp = await request(cfg, 'GET', path)
  return { comments: resp.data, pagination: resp.pagination }
}

// ---------- 用户 ----------

export interface QueryUserArgs {
  emails?: string[]
  userKeys?: string[]
}

/** POST /open_api/user/query → 用户详情(user_key/name_cn/email 等;邮箱→user_key 反查用)。 */
export async function queryUser(cfg: MeegoApiConfig, args: QueryUserArgs): Promise<unknown> {
  const body: Record<string, unknown> = {}
  if (args.userKeys !== undefined && args.userKeys.length > 0) body.user_keys = args.userKeys
  if (args.emails !== undefined && args.emails.length > 0) body.emails = args.emails
  if (Object.keys(body).length === 0) {
    throw new TBError('invalid_argument', 'query_user 需要 user_keys 或 emails 至少一项')
  }
  const resp = await request(cfg, 'POST', '/open_api/user/query', body)
  return { users: resp.data }
}

// ---------- 工作项查询 ----------

export interface FilterWorkItemsArgs {
  pageNum?: number
  pageSize?: number
  projectKey: string
  /** 按人筛:open_api filter 的 user_keys 内建"该用户全角色并集"(经办人/研发/负责人等),无需手写 OR。 */
  userKeys?: string[]
  workItemName?: string
  workItemTypeKeys?: string[]
}

/**
 * POST /open_api/:project_key/work_item/filter → 工作项列表(含 work_item_status)。
 * 替代旧 meego 的 search_by_mql "按人查名下工作项":user_keys 由 open_api 内建全角色并集,
 * 比手写 `__经办人 OR __研发 OR 当前负责人` 更准(不同工作项类型角色不同,后端已算好)。
 * 查询按字段筛,与调用方身份无关;X-USER-KEY 仅用于鉴权。
 */
export async function filterWorkItems(
  cfg: MeegoApiConfig,
  args: FilterWorkItemsArgs,
): Promise<unknown> {
  const body: Record<string, unknown> = {}
  if (args.workItemName !== undefined) body.work_item_name = args.workItemName
  if (args.userKeys !== undefined && args.userKeys.length > 0) body.user_keys = args.userKeys
  if (args.workItemTypeKeys !== undefined && args.workItemTypeKeys.length > 0) {
    body.work_item_type_keys = args.workItemTypeKeys
  }
  if (args.pageNum !== undefined) body.page_num = args.pageNum
  if (args.pageSize !== undefined) body.page_size = args.pageSize
  const path = `/open_api/${encodeURIComponent(args.projectKey)}/work_item/filter`
  const resp = await request(cfg, 'POST', path, body)
  return { work_items: resp.data, pagination: resp.pagination }
}
