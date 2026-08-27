/**
 * 「我的 key」自助面的纯逻辑:有效期换算与 scope 的人话化。
 *
 * 与 skConfig(admin 面)分开:自助面**没有** owner / scopes / registerPaths 表单
 * —— 服务端把 owner 钉在 ctx.owner、把 scopes 钉成登录默认那套(见 core 的
 * builtin/myKeys.ts)。这里只剩「描述」与「有效期」两件事。
 *
 * 来源(origin)与用户描述由服务端拆好后直接给:`list` 返回结构化 `origin` 字段,
 * `description` 只含用户自己写的那段。前端不再解析 description 前缀 —— 那些前缀是
 * 存储层实现细节,散落在 core/app 三个常量里,前端 split 等于把它们变成隐式契约。
 */

import type { Action, MyKeyInfo, MyKeyOrigin, Scope } from '@/lib/types'

export const ORIGIN_LABEL: Record<MyKeyOrigin, string> = {
  self: '我签发的',
  login: '登录会话',
  delegation: '授权应用',
  other: '其它来源',
}

// ---- 有效期 ----

export type ExpiryPreset = '7d' | '30d' | '90d' | 'custom' | 'forever'

export const EXPIRY_OPTIONS: Array<{ label: string, value: ExpiryPreset }> = [
  { value: 'forever', label: '永久有效' },
  { value: '7d', label: '7 天后过期' },
  { value: '30d', label: '30 天后过期' },
  { value: '90d', label: '90 天后过期' },
  { value: 'custom', label: '自定义日期' },
]

const PRESET_DAYS: Partial<Record<ExpiryPreset, number>> = { '7d': 7, '30d': 30, '90d': 90 }

export interface MyKeyFormState {
  /** 'custom' 时的 `YYYY-MM-DD`(<input type="date"> 原生值)。 */
  customDate: string
  description: string
  preset: ExpiryPreset
}

export const INITIAL_MY_KEY_FORM: MyKeyFormState = {
  description: '',
  preset: 'forever',
  customDate: '',
}

/**
 * 表单 → `expiresAt`。返回 `undefined` = 永久(create 时不传该字段)。
 *
 * 自定义日期取**当地当天 23:59:59**,而不是 UTC 零点:用户填「9 月 1 日」的意思是
 * 「用到 9 月 1 日结束」,按 UTC 零点算会在 UTC+8 的当天早上八点就失效。
 */
export function buildExpiresAt(state: MyKeyFormState, now = Date.now()): string | undefined {
  if (state.preset === 'forever') return undefined
  const days = PRESET_DAYS[state.preset]
  if (days !== undefined) return new Date(now + days * 86_400_000).toISOString()
  const parts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(state.customDate.trim())
  if (parts === null) throw new Error('请选择一个有效期日期。')
  const [year, month, day] = [Number(parts[1]), Number(parts[2]), Number(parts[3])]
  const at = new Date(year, month - 1, day, 23, 59, 59)
  if (Number.isNaN(at.getTime()) || at.getMonth() !== month - 1 || at.getDate() !== day) {
    throw new Error('日期不存在，请重新选择。')
  }
  if (at.getTime() <= now) throw new Error('有效期需要晚于当前时间。')
  return at.toISOString()
}

/** create 入参:两项都可选,永久则不带 expiresAt。 */
export function buildMyKeyCreateArgs(state: MyKeyFormState, now = Date.now()) {
  const description = state.description.trim()
  const expiresAt = buildExpiresAt(state, now)
  return {
    ...(description !== '' ? { description } : {}),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  }
}

/**
 * update 入参。与 create 的差别是**改成永久要显式传空串** —— 字段缺省表示「不动」,
 * 只有 `expiresAt: ''` 才是「清除过期」(见 core 的 myKeys update)。
 */
export function buildMyKeyUpdateArgs(id: string, state: MyKeyFormState, now = Date.now()) {
  const expiresAt = buildExpiresAt(state, now)
  return {
    id,
    description: state.description.trim(),
    expiresAt: expiresAt ?? '',
  }
}

/**
 * 已有 key → 编辑表单初值(有过期时间的落到「自定义日期」,便于原地微调)。
 *
 * `description` 服务端已剥好来源前缀,直接用;登录会话 key 没有用户描述(undefined),
 * 按空串处理。
 */
export function toMyKeyForm(key: MyKeyInfo): MyKeyFormState {
  const description = key.description ?? ''
  if (key.expiresAt === undefined) return { description, preset: 'forever', customDate: '' }
  const at = new Date(key.expiresAt)
  if (Number.isNaN(at.getTime())) return { description, preset: 'forever', customDate: '' }
  const pad = (value: number) => String(value).padStart(2, '0')
  return {
    description,
    preset: 'custom',
    customDate: `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`,
  }
}

// ---- scope 的人话化 ----

const ACTION_LABEL: Record<Action, string> = {
  read: '查看',
  call: '调用',
  write: '写入',
  register: '注册节点',
  admin: '管理',
}

/** 登录默认那套 scope 的 pattern → 用户看得懂的区域名。 */
const PATTERN_LABEL: Record<string, string> = {
  '**': '全部节点',
  'mcp/**': 'MCP 工具',
  'plugins/**': '插件工具',
  'skills/**': '技能库',
  'docs/**': '文档',
  'system/usercred': '我的凭证',
  'system/my-keys': '我的密钥',
}

export interface ScopeLine {
  /** 「查看 · 调用」这类中文动作串。 */
  actions: string
  /** deny 规则要显眼:它优先于一切 allow。 */
  deny: boolean
  /** 人话区域名(未知 pattern 回落到 pattern 本身)。 */
  label: string
  /** 原始 glob,挂 title 供需要精确值的人查。 */
  pattern: string
}

/** scopes → 可读行。不做 JSON 直糊:每条一行「区域 + 能做什么」。 */
export function describeScopes(scopes: Scope[]): ScopeLine[] {
  return scopes.map(scope => ({
    pattern: scope.pattern,
    label: PATTERN_LABEL[scope.pattern] ?? scope.pattern,
    actions: scope.actions.map(action => ACTION_LABEL[action] ?? action).join(' · '),
    deny: scope.effect === 'deny',
  }))
}
