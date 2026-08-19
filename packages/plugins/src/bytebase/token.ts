/**
 * Bytebase 服务账号(Service Account)访问令牌换发与进程内缓存。
 *
 * - 换发:`POST {baseUrl}/v1/auth/login`,body `{email, password: <service_key>, web:false}`
 *   → `{token}`。SA 的 token 由 Bytebase 以 `GenerateAPIToken` 签发,audience
 *   `bb.user.access`、**有效期固定 1h**,响应体不含 expires_in——过期时刻只能从 JWT
 *   `exp` claim 读(decodeExp);读不到时按保守 DEFAULT_TTL_MS 记。
 * - 凭证(email/service_key)不由 plugin 自持:每次调用由平台经 X-TB-Upstream-Auth
 *   传入(挂载 config.authRef 平台代解析)——同一 plugin 部署可服务多个 Bytebase
 *   实例/账号的挂载,故缓存**按 `<baseUrl>|<email>|<sha256(service_key) 前16hex>` 键控**
 *   (模式同 feishu/tat.ts,但 key 摘要必须进键,见 cacheKey 注释的实测教训)。
 * - 缓存在 isolate 内存(无 KV):token 最长 1h,isolate 回收即重换发;换发是幂等轻请求,
 *   不值得引入持久层。
 * - 刷新余量 5min:调用时刻剩余不足余量即懒换发。
 * - `force` 绕过缓存直接换发——上游 401 的纠错路径不得回读缓存(教训同网关 mcp
 *   会话空列表防御:凡纠错路径都绕开缓存读)。
 *
 * 注意:Bytebase 对 login 有失败锁定(checkPasswordLockout,按 email 计数)。service_key
 * 轮换后忘了更新平台凭证会连续换发失败并可能触发锁定——换发失败一律 unavailable 且
 * `retryable:false`,不重试放大。
 */

import { base64urlDecode, TBError } from '@tool-bridge/core'
import { createGuardedFetch } from '../_runtime/guardedFetch'

export const LOGIN_PATH = '/v1/auth/login'

const REFRESH_MARGIN_MS = 5 * 60_000

/** JWT 无 exp 时的保守 TTL(Bytebase SA token 实际 1h,留足余量)。 */
const DEFAULT_TTL_MS = 30 * 60_000

// service_key 在 JSON body 中,307/308 跨源跳转会原样转发;Bytebase 换发端点不应跨源。
const bytebaseAuthFetch = createGuardedFetch({ crossOriginRedirect: 'error' })

interface CachedToken {
  expiresAtMs: number
  token: string
}

const cache = new Map<string, CachedToken>()

/** 测试用:清空进程内 token 缓存。 */
export function clearTokenCache(): void {
  cache.clear()
}

export interface TokenConfig {
  /** Bytebase 实例 base URL(无尾斜杠),如 https://bytebase.example.com。 */
  baseUrl: string
  /** SA 邮箱,形如 `<name>@service.bytebase.com`。 */
  email: string
  /** SA service key(创建/轮换时一次性返回,形如 bbs_xxx),换发时作 password 传。 */
  serviceKey: string
}

interface LoginResponse {
  mfaTempToken?: string
  token?: string
}

/**
 * 缓存键:实例 + 账号 + **service_key 摘要**。
 *
 * 摘要必须进键(2026-07-29 生产实测踩到):只用 `baseUrl|email` 时,拿错 service_key 的请求
 * 会命中同 email 的有效缓存并成功返回 —— 既破坏"plugin 无凭证即空壳"(泄漏 PLUGIN_TOKEN +
 * 猜到 SA 邮箱即可白蹭令牌),也让 service_key 轮换在旧令牌到期前不生效。摘要用
 * SHA-256 前 16 hex(单向,不在键里留明文;够长以避免碰撞)。
 */
async function cacheKey(cfg: TokenConfig): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(cfg.serviceKey),
  )
  const hex = Array.from(new Uint8Array(digest).slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
  return `${cfg.baseUrl}|${cfg.email}|${hex}`
}

/** MCP 会话缓存键:与令牌缓存同粒度(换了 key 就是另一条身份链,会话不得复用)。 */
export async function sessionKey(cfg: TokenConfig): Promise<string> {
  return cacheKey(cfg)
}

/**
 * 从 JWT 载荷读 `exp`(秒)转毫秒;非 JWT / 无 exp → undefined(调用方按 DEFAULT_TTL_MS)。
 * 只解不验签:签名由 Bytebase 自己校验,这里只为算缓存到期。
 */
export function decodeExp(token: string): number | undefined {
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  const payload = parts[1]
  if (payload === undefined || payload === '') return undefined
  try {
    const claims = JSON.parse(new TextDecoder().decode(base64urlDecode(payload))) as {
      exp?: unknown
    }
    return typeof claims.exp === 'number' ? claims.exp * 1000 : undefined
  } catch {
    return undefined
  }
}

/** 取可用访问令牌:该实例+账号+key 的缓存余量充足直接返回,否则换发并回填。 */
export async function accessToken(cfg: TokenConfig, force = false): Promise<string> {
  const key = await cacheKey(cfg)
  const cached = cache.get(key)
  if (!force && cached !== undefined && cached.expiresAtMs - Date.now() > REFRESH_MARGIN_MS) {
    return cached.token
  }
  let resp: Response
  try {
    resp = await bytebaseAuthFetch(`${cfg.baseUrl}${LOGIN_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: cfg.email, password: cfg.serviceKey, web: false }),
    })
  } catch (err) {
    throw new TBError(
      'unavailable',
      `Bytebase 换发访问令牌网络失败:${err instanceof Error ? err.message : String(err)}`,
      { retryable: true },
    )
  }
  const body = (await resp.json().catch(() => null)) as LoginResponse | null
  const token = body?.token
  if (!resp.ok || typeof token !== 'string' || token === '') {
    // MFA 只可能出现在人类账号上;SA 走到这里说明凭证配成了普通用户,指出来省排查。
    const hint
      = typeof body?.mfaTempToken === 'string' && body.mfaTempToken !== ''
        ? ':凭证似为需 MFA 的人类账号,请改用 Service Account'
        : ''
    throw new TBError(
      'unavailable',
      `Bytebase 换发访问令牌失败:HTTP ${resp.status}${hint}(核对 email 与 service_key,注意连续失败会触发登录锁定)`,
      { retryable: false },
    )
  }
  cache.set(key, {
    token,
    expiresAtMs: decodeExp(token) ?? Date.now() + DEFAULT_TTL_MS,
  })
  return token
}
