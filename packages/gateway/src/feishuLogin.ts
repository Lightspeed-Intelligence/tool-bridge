/**
 * 飞书登录自助换 key(方案 A:纯 open_id,不校验邮箱)。
 *
 * 流程两段,状态全在网关侧闭环:
 * - 发起(`GET /login`,tbApp 树外免认证挂接):生成加密 state(CSRF nonce + exp),
 *   302 跳飞书 `/authen/v1/authorize`。
 * - 回调(`GET /~feishu/callback`,树外免认证):解密校验 state → code 换
 *   user_access_token → `/authen/v1/user_info` 拿 open_id → **rotate 签发** SK
 *   (同 owner 旧 key 先删再签,因明文只返回一次)→ 回调页一次性展示。
 *
 * 准入:能走完企业飞书 OAuth = 本企业成员,不校验邮箱域(方案 A)。
 * app 凭证:复用 feishu plugin 的 SecretStore 引用(默认 "feishu-app",{app_id,app_secret})。
 * state 加密:AES-256-GCM,密钥派生自 TB_SECRET_ENCRYPTION_KEY(域前缀区隔 mcp-oauth)。
 */

import {
  base64urlDecode,
  base64urlEncode,
  type Scope,
  type SecretKeyInput,
  type SKRegistryStore,
  TBError,
  type Timestamp,
} from '@tool-bridge/core'

/** 飞书开放平台 base(私有化部署可 override,当前固定公网)。 */
export const FEISHU_BASE = 'https://open.feishu.cn'

/** 登录回调路径(树外免认证;飞书后台需登记 `<origin>/~feishu/callback`)。 */
export const FEISHU_CALLBACK_PATH = '/~feishu/callback'

/** state TTL:发起 → 回调时限;过期一律拒,防 code 重放窗口拉长。 */
const STATE_TTL_SEC = 600

/** 默认签发的 key 有效期(秒):90 天,过期重新登录自动 rotate。 */
export const DEFAULT_KEY_TTL_SEC = 90 * 24 * 3600

/** 本流程签发的 key 打标记(description 前缀),rotate 时据此识别自己签的 key。 */
export const LOGIN_KEY_TAG = 'feishu-login'

/**
 * 登录 key 的默认 scope:mcp / plugins / skills 的 read+call+write。
 * 不含 system/** 、device/** ,不含 admin。
 */
export function defaultLoginScopes(): Scope[] {
  const actions: Scope['actions'] = ['read', 'call', 'write']
  return [
    { pattern: 'mcp/**', actions },
    { pattern: 'plugins/**', actions },
    { pattern: 'skills/**', actions },
  ]
}

// ---------- state(AES-256-GCM,零存储;域前缀区隔 mcp-oauth 的 state 密钥)----------

/** state 载荷:n = CSRF nonce,exp = 过期时刻(epoch 秒)。 */
export interface LoginStatePayload {
  exp: number
  n: string
}

/** state 加密密钥:SHA-256("tb-feishu-login-state:" + 主密钥)派生 32 字节(域分离)。 */
async function stateCryptoKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`tb-feishu-login-state:${secret}`),
  )
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/** 加密 state:base64url(iv).base64url(ciphertext);GCM 自带完整性。 */
export async function sealLoginState(payload: LoginStatePayload, secret: string): Promise<string> {
  const key = await stateCryptoKey(secret)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(payload)),
  )
  return `${base64urlEncode(iv)}.${base64urlEncode(new Uint8Array(ciphertext))}`
}

/** 解密 state;任何失败(格式/解密/形状)→ null。过期判定留给调用方(便于测钟)。 */
export async function openLoginState(
  state: string,
  secret: string,
): Promise<LoginStatePayload | null> {
  const dot = state.indexOf('.')
  if (dot <= 0) return null
  try {
    const key = await stateCryptoKey(secret)
    const iv = base64urlDecode(state.slice(0, dot))
    const ciphertext = base64urlDecode(state.slice(dot + 1))
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> },
      key,
      ciphertext as Uint8Array<ArrayBuffer>,
    )
    const payload = JSON.parse(new TextDecoder().decode(plain)) as LoginStatePayload
    if (typeof payload.n !== 'string' || typeof payload.exp !== 'number') return null
    return payload
  } catch {
    return null
  }
}

/** 生成一段新 state(nonce 随机 + exp=now+TTL);返回加密串。 */
export async function newLoginState(secret: string, nowMs: number): Promise<string> {
  const nonce = base64urlEncode(crypto.getRandomValues(new Uint8Array(16)))
  return await sealLoginState(
    { n: nonce, exp: Math.floor(nowMs / 1000) + STATE_TTL_SEC },
    secret,
  )
}

// ---------- 飞书凭证 ----------

/** SecretStore 里 feishu-app 的形状:{app_id, app_secret}(与 feishu plugin 一致)。 */
export interface FeishuAppCredential {
  app_id: string
  app_secret: string
}

/** 解析 SecretStore resolve 出的凭证 JSON;形状不符 → unavailable。 */
export function parseFeishuCredential(raw: string | undefined, refName: string): FeishuAppCredential {
  if (raw === undefined) {
    throw new TBError('unavailable', `飞书登录凭证 '${refName}' 无法解析(SecretStore 未配置?)`, {
      retryable: false,
    })
  }
  try {
    const v = JSON.parse(raw) as Partial<FeishuAppCredential>
    if (typeof v.app_id === 'string' && v.app_id !== '' && typeof v.app_secret === 'string' && v.app_secret !== '') {
      return { app_id: v.app_id, app_secret: v.app_secret }
    }
  } catch {
    // fallthrough
  }
  throw new TBError('unavailable', `凭证 '${refName}' 不是 {"app_id","app_secret"} 形状的 JSON`, {
    retryable: false,
  })
}

// ---------- 飞书 OAuth(authorization code) ----------

/** 拼飞书授权页 URL(浏览器 302 落点)。方案 A 不带 scope 参数,只取默认 open_id。 */
export function buildAuthorizeUrl(appId: string, redirectUri: string, state: string): string {
  const u = new URL('/open-apis/authen/v1/authorize', FEISHU_BASE)
  u.searchParams.set('app_id', appId)
  u.searchParams.set('redirect_uri', redirectUri)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('state', state)
  return u.toString()
}

interface TokenResponse {
  // 兼容旧版直返在顶层的形状
  access_token?: string
  code?: number
  data?: { access_token?: string }
  msg?: string
}

/**
 * code → user_access_token。走 v2 OIDC 端点(app_access_token 免带,PKCE 无;
 * 用 app_id/app_secret 直接换)。失败 → unavailable。
 */
export async function exchangeUserToken(
  cred: FeishuAppCredential,
  code: string,
  redirectUri: string,
): Promise<string> {
  let resp: Response
  try {
    resp = await fetch(`${FEISHU_BASE}/open-apis/authen/v2/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: cred.app_id,
        client_secret: cred.app_secret,
        code,
        redirect_uri: redirectUri,
      }),
    })
  } catch (err) {
    throw new TBError('unavailable', `飞书 token 换发网络失败:${err instanceof Error ? err.message : String(err)}`, {
      retryable: true,
    })
  }
  const body = (await resp.json().catch(() => null)) as TokenResponse | null
  const token = body?.access_token ?? body?.data?.access_token
  if (!resp.ok || body === null || typeof token !== 'string' || token === '') {
    throw new TBError(
      'unavailable',
      `飞书 token 换发失败:HTTP ${resp.status} code=${body?.code ?? '?'} ${body?.msg ?? ''}`.trim(),
      { retryable: false },
    )
  }
  return token
}

interface UserInfo {
  name?: string
  open_id: string
}

interface UserInfoResponse {
  code?: number
  data?: { name?: string, open_id?: string }
  msg?: string
}

/** user_access_token → 本人 open_id(方案 A 只取 open_id + name)。 */
export async function fetchUserInfo(userToken: string): Promise<UserInfo> {
  let resp: Response
  try {
    resp = await fetch(`${FEISHU_BASE}/open-apis/authen/v1/user_info`, {
      headers: { authorization: `Bearer ${userToken}` },
    })
  } catch (err) {
    throw new TBError('unavailable', `飞书 user_info 网络失败:${err instanceof Error ? err.message : String(err)}`, {
      retryable: true,
    })
  }
  const body = (await resp.json().catch(() => null)) as UserInfoResponse | null
  const openId = body?.data?.open_id
  if (!resp.ok || body === null || body.code !== 0 || typeof openId !== 'string' || openId === '') {
    throw new TBError(
      'unavailable',
      `飞书 user_info 失败:HTTP ${resp.status} code=${body?.code ?? '?'} ${body?.msg ?? ''}`.trim(),
      { retryable: false },
    )
  }
  return { open_id: openId, ...(typeof body.data?.name === 'string' ? { name: body.data.name } : {}) }
}

// ---------- rotate 签发 ----------

/** owner ref:方案 A 用 open_id 唯一标识登录者。 */
export function loginOwner(openId: string): string {
  return `user:${openId}`
}

/**
 * rotate 签发:删除同 owner 且由本流程签发(description 带 LOGIN_KEY_TAG)的旧 key,
 * 再签一把新 key。明文 secret 只在返回值里出现一次。
 * @returns { keyId, secret }
 */
export async function rotateLoginKey(
  sk: SKRegistryStore,
  openId: string,
  now: Timestamp,
  opts?: { scopes?: Scope[], ttlSec?: number },
): Promise<{ keyId: string, secret: string }> {
  const owner = loginOwner(openId)
  // 删旧:遍历 list 找同 owner + 本流程标记的 key(key 量小,可接受;无 owner 索引)。
  // 分页遍历直至游标耗尽。
  let cursor: string | undefined
  do {
    const page = await sk.list(cursor !== undefined ? { limit: 200, cursor } : { limit: 200 })
    for (const k of page.items) {
      if (k.owner === owner && (k.description ?? '').startsWith(LOGIN_KEY_TAG)) {
        await sk.delete(k.id)
      }
    }
    cursor = page.cursor
  } while (cursor !== undefined)

  const ttlSec = opts?.ttlSec ?? DEFAULT_KEY_TTL_SEC
  const expiresAt = new Date(Date.parse(now) + ttlSec * 1000).toISOString()
  const input: SecretKeyInput = {
    owner,
    description: `${LOGIN_KEY_TAG} @ ${now}`,
    scopes: opts?.scopes ?? defaultLoginScopes(),
    expiresAt,
  }
  const { key, secret } = await sk.write(input, now)
  return { keyId: key.id, secret }
}

// ---------- meego 自动绑定(open_id → user_key,best-effort) ----------

/**
 * meego 绑定所需的最小注入面(解耦 Hono/provider):
 * - listMemberUserKeys:拉 meego 空间成员的 user_key 候选集(分页已在实现内收敛)
 * - queryOutId:给定 user_key 批量取 out_id(=飞书 open_id);返回 { user_key: out_id }
 * - getMeegoUserKeys / setMeegoUserKeys:读/整体写回 plugins/meego 的 providerConfig.userKeys
 */
export interface MeegoBindDeps {
  getMeegoUserKeys: () => Promise<Record<string, string>>
  listMemberUserKeys: () => Promise<string[]>
  queryOutId: (userKeys: string[]) => Promise<Record<string, string>>
  setMeegoUserKeys: (next: Record<string, string>) => Promise<void>
}

export type MeegoBindResult
  = | { bound: true, userKey: string }
    | { bound: false, reason: string }

/**
 * 把新签发的 keyId 绑定到 meego 操作人身份:按 open_id 反查 user_key,写入映射表。
 * best-effort:任何环节失败(反查不到 / meego 不可用 / open_id 跨 app 不对齐)都不抛,
 * 返回 { bound:false, reason },由调用方在回调页提示"meego 身份待管理员绑定"。
 */
export async function bindMeegoIdentity(
  deps: MeegoBindDeps,
  keyId: string,
  openId: string,
): Promise<MeegoBindResult> {
  try {
    const candidates = await deps.listMemberUserKeys()
    if (candidates.length === 0) return { bound: false, reason: 'meego 空间无成员候选' }
    // 批量取 out_id,匹配 open_id。meego query_user 一次限 20,分批。
    let matched: string | undefined
    for (let i = 0; i < candidates.length && matched === undefined; i += 20) {
      const batch = candidates.slice(i, i + 20)
      const outIds = await deps.queryOutId(batch)
      for (const [uk, outId] of Object.entries(outIds)) {
        if (outId === openId) {
          matched = uk
          break
        }
      }
    }
    if (matched === undefined) {
      return { bound: false, reason: 'open_id 未匹配到 meego 成员(可能跨 app 不对齐)' }
    }
    const current = await deps.getMeegoUserKeys()
    await deps.setMeegoUserKeys({ ...current, [keyId]: matched })
    return { bound: true, userKey: matched }
  } catch (err) {
    return { bound: false, reason: err instanceof Error ? err.message : String(err) }
  }
}

// ---------- 回调结果页 ----------

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** 失败页(不含机密)。 */
export function renderLoginFailedHtml(detail: string): Response {
  const safe = escapeHtml(detail)
  const body = `<!doctype html>
<html><head><meta charset="utf-8"><title>登录失败 · tool-bridge</title>
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:80vh;margin:0}
main{text-align:center}h1{font-size:1.4rem}p{color:#555}</style></head>
<body><main><h1>❌ 登录失败</h1><p>${safe}</p><p>可关闭本页后重试。</p></main></body></html>`
  return new Response(body, {
    status: 400,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': 'default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
  })
}

/**
 * 成功页:一次性展示 SK + baseUrl + tb login 命令。SK 是机密,页面 no-store、CSP 锁死、
 * 不外连不加载脚本;secret 经 escapeHtml 后注入(SK 字符集安全,双保险)。
 */
export function renderLoginSuccessHtml(opts: {
  baseUrl: string
  meegoNote?: string
  name?: string
  secret: string
}): Response {
  const secret = escapeHtml(opts.secret)
  const baseUrl = escapeHtml(opts.baseUrl)
  const who = opts.name !== undefined ? escapeHtml(opts.name) : ''
  const meego = opts.meegoNote !== undefined ? `<p class="note">${escapeHtml(opts.meegoNote)}</p>` : ''
  const body = `<!doctype html>
<html><head><meta charset="utf-8"><title>登录成功 · tool-bridge</title>
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:80vh;margin:0;padding:1rem}
main{max-width:640px;width:100%}h1{font-size:1.3rem}code,pre{background:#f4f4f5;border-radius:6px}
pre{padding:.8rem 1rem;overflow-x:auto;user-select:all}.k{font-weight:600}
.note{color:#b45309;background:#fffbeb;padding:.6rem .8rem;border-radius:6px}
.warn{color:#666;font-size:.85rem}</style></head>
<body><main>
<h1>✅ 登录成功${who ? `,${who}` : ''}</h1>
<p>这是你的 Secret Key(<span class="k">仅显示这一次</span>,请立即保存):</p>
<pre>${secret}</pre>
<p>命令行接入:</p>
<pre>tb login --base-url ${baseUrl} --sk ${secret}</pre>
${meego}
<p class="warn">此 Key 可调用 mcp / plugins / skills(读+调用+写),90 天后过期,重新登录即自动换发。</p>
</main></body></html>`
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': 'default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
  })
}
