import { base64urlEncode, HEADER_TB_UPSTREAM_AUTH } from '@tool-bridge/core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { env, SELF } from 'cloudflare:test'
import { clearTokenCache, decodeExp } from '../src/token'
import { clearSessionCache } from '../src/bytebaseMcp'

// plugin-bytebase 集成测试:契约面 / envelope 鉴权 / 凭证经 X-TB-Upstream-Auth 传入 /
// SA 访问令牌换发与缓存(按 exp 算余量)/ 上游 401 强制重换发 / 白名单双闸 / 多实例不串号。
// Bytebase login 接口与 MCP 上游全部 fetch mock,默认离线确定性。测试与 Worker 同 isolate
// (vitest-pool-workers):可直接清模块级缓存、改 env 绑定。

const BASE_URL = 'https://bytebase.mock'
const LOGIN_URL = `${BASE_URL}/v1/auth/login`
const MCP_URL = `${BASE_URL}/mcp`
const PLUGIN_TOKEN = 'tbp_test_token'
const SERVICE_KEY = 'bbs_test_key'

/** 平台注入形态:base64url JSON {email,service_key[,base_url]}。 */
function upstreamAuth(
  email = 'tool-bridge@service.bytebase.com',
  serviceKey = SERVICE_KEY,
  baseUrl?: string,
): string {
  return base64urlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        email,
        service_key: serviceKey,
        ...(baseUrl !== undefined ? { base_url: baseUrl } : {}),
      }),
    ),
  )
}

/** 造一个形状真实的 JWT(仅 base64url payload 有意义;plugin 只读 exp 不验签)。 */
function fakeJwt(sub: string, expMs: number, seq: number): string {
  const b64 = (o: unknown): string =>
    base64urlEncode(new TextEncoder().encode(JSON.stringify(o)))
  return [
    b64({ alg: 'HS256', kid: 'v1', typ: 'JWT' }),
    b64({ aud: ['bb.user.access'], exp: Math.floor(expMs / 1000), iss: 'bytebase', sub }),
    `sig-${seq}`,
  ].join('.')
}

/**
 * Bytebase 侧 mock:login(签发递增 JWT,exp = 现在 +1h,同真实 SA token)+ Streamable HTTP
 * MCP 上游(校验 Bearer ∈ 有效集,否则 401;陈旧 sessionId → 404,同真实上游实测)。
 * `revokeAllTokens()` 模拟 service_key 轮换/SA 停用:老 token 请求一律 401。
 */
function bytebaseMock(tools: Array<{ description: string, name: string }>) {
  const validTokens = new Set<string>()
  const sessions = new Set<string>()
  /** sessionId → 建会话时携带的 token(模拟上游把 token 绑进 session context)。 */
  const sessionToken = new Map<string, string>()
  let tokenSeq = 0
  let sessionSeq = 0
  let loginCalls = 0

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input))

    if (url.href === LOGIN_URL) {
      loginCalls += 1
      const body = JSON.parse(String(init?.body)) as {
        email?: string
        password?: string
        web?: boolean
      }
      // 任意 email + 固定 service_key 视为有效(多实例/多账号用例用不同 email)。
      if (!body.email || body.password !== SERVICE_KEY) {
        return new Response(JSON.stringify({ message: 'invalid email or password' }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        })
      }
      tokenSeq += 1
      const token = fakeJwt(body.email, Date.now() + 3_600_000, tokenSeq)
      validTokens.add(token)
      return new Response(JSON.stringify({ token }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    if (url.href === MCP_URL) {
      const headers = new Headers(init?.headers)
      const auth = headers.get('authorization') ?? ''
      const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : ''
      if (!validTokens.has(bearer)) {
        return new Response(JSON.stringify({ message: 'authorization required' }), {
          status: 401,
          headers: {
            'content-type': 'application/json',
            'www-authenticate': 'Bearer realm="OAuth", error="invalid_token"',
          },
        })
      }
      const body = JSON.parse(String(init?.body)) as {
        id?: number | string
        method: string
        params?: { arguments?: unknown, name?: string, protocolVersion?: string }
      }
      const sid = headers.get('mcp-session-id')
      // 真实上游:有效 token + 未知/过期 session → 404(会话层失效信号)。
      if (sid !== null && !sessions.has(sid)) {
        return new Response(JSON.stringify({ message: 'session not found' }), { status: 404 })
      }
      const rpc = (result: unknown, extra: Record<string, string> = {}) =>
        new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), {
          status: 200,
          headers: { 'content-type': 'application/json', ...extra },
        })
      if (body.method === 'initialize') {
        sessionSeq += 1
        const fresh = `sess-${sessionSeq}`
        sessions.add(fresh)
        // 真实上游把建会话时的 token 绑进 session context,后续 tools/call 用的是它
        // (不看本次请求头)。这里记下来以复现"会话内令牌过期"。
        sessionToken.set(fresh, bearer)
        return rpc(
          {
            protocolVersion: body.params?.protocolVersion ?? '2025-06-18',
            capabilities: { tools: { listChanged: true } },
            serverInfo: { name: 'bytebase', version: '3.19.0' },
          },
          { 'mcp-session-id': fresh },
        )
      }
      if (body.method === 'notifications/initialized') return new Response(null, { status: 202 })
      if (body.method === 'tools/list') {
        // Bytebase 3.19.0 实测只发 name/description/inputSchema,**不带 annotations**
        // ——plugin 须按工具名兜底 effect(否则平台侧 destructive 二次确认失效)。
        return rpc({ tools: tools.map(t => ({ ...t, inputSchema: { type: 'object' } })) })
      }
      if (body.method === 'tools/call') {
        // 会话内令牌过期:用**建会话时**那个 token 判定,且以 HTTP 200 + ToolResult
        // 文本(不是 401)返回业务错误 —— 与真实上游一致。
        const bound = sid !== null ? sessionToken.get(sid) : undefined
        if (bound !== undefined && !validTokens.has(bound)) {
          return rpc({
            content: [{ type: 'text', text: 'failed to list databases: HTTP 401: access token expired' }],
            isError: true,
          })
        }
        return rpc({
          content: [
            {
              type: 'text',
              text: `bytebase:${body.params?.name}:${JSON.stringify(body.params?.arguments)}`,
            },
          ],
        })
      }
      return rpc({})
    }

    return new Response('unexpected upstream', { status: 500 })
  })

  return {
    fetchMock,
    loginCalls: () => loginCalls,
    revokeAllTokens: () => validTokens.clear(),
    expireSessions: () => sessions.clear(),
    /**
     * 让**已绑进会话**的 token 在上游侧失效(其它 token 不动)。
     *
     * 复现「会话内令牌过期」的要点是让"请求头上的 token"与"会话里绑的 token"分离:
     * 直接吊销全部会导致头也失效、退化成已有用例覆盖的 401 路径。配合推进系统时钟
     * (plugin 越过刷新余量后会自行换发新令牌进请求头)即得真实生产序列。
     */
    expireSessionBoundTokens: () => {
      for (const bound of sessionToken.values()) validTokens.delete(bound)
    },
  }
}

const TOOLS = [
  { name: 'query_database', description: 'Execute a SQL query' },
  { name: 'get_schema', description: 'Inspect a database schema' },
  { name: 'propose_database_change', description: 'Run DDL/DML changes' },
]

async function envelope(
  tool: string,
  args: Record<string, unknown>,
  init: RequestInit = {},
): Promise<Response> {
  return SELF.fetch('https://plugin.test/', {
    method: 'POST',
    ...init,
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${PLUGIN_TOKEN}`,
      'x-tb-request-id': crypto.randomUUID(),
      [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(),
      ...(init.headers ?? {}),
    },
    body: JSON.stringify({ tool, arguments: args }),
  })
}

beforeEach(() => {
  clearTokenCache()
  clearSessionCache()
  // 白名单默认放行全部;个别用例临时改绑定,这里复位避免用例间串味。
  ;(env as { BYTEBASE_ALLOWED_TOOLS: string }).BYTEBASE_ALLOWED_TOOLS = ''
})

describe('契约面(生命周期 GET,不鉴权)', () => {
  it('healthz / ~describe / ~help(DSL 与 HelpJson)形状符合 tool-provider/v1', async () => {
    const health = await SELF.fetch('https://plugin.test/healthz')
    expect(health.status).toBe(200)
    expect(await health.json()).toEqual({ healthy: true })

    const describeRes = await SELF.fetch('https://plugin.test/~describe')
    expect(await describeRes.json()).toEqual({
      kind: 'tool-provider',
      interfaceVersion: 'tool-provider/v1',
    })

    const helpJson = await SELF.fetch('https://plugin.test/~help', {
      headers: { accept: 'application/json' },
    })
    const cmds = ((await helpJson.json()) as { cmds: Array<{ name: string }> }).cmds
    expect(cmds.map(c => c.name).sort()).toEqual(['Call', 'Get', 'List'])

    const helpDsl = await SELF.fetch('https://plugin.test/~help')
    expect(await helpDsl.text()).toContain('cmd List')
  })
})

describe('envelope 鉴权与凭证传入', () => {
  it('无 / 错 Bearer → 401 TBError 形状', async () => {
    const none = await envelope('List', {}, { headers: { authorization: '' } })
    expect(none.status).toBe(401)
    const bad = await envelope('List', {}, { headers: { authorization: 'Bearer wrong' } })
    expect(bad.status).toBe(401)
    expect(((await bad.json()) as { code: string }).code).toBe('permission_denied')
  })

  it('缺 X-TB-Upstream-Auth → 503(挂载缺 authRef 是配置错误);坏形状 → 400;缺字段 → 400', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const missing = await envelope('List', {}, { headers: { [HEADER_TB_UPSTREAM_AUTH]: '' } })
    expect(missing.status).toBe(503)
    expect(((await missing.json()) as { message: string }).message).toContain('authRef')
    expect(upstream.loginCalls()).toBe(0) // 缺凭证不打 Bytebase

    const garbage = await envelope(
      'List',
      {},
      { headers: { [HEADER_TB_UPSTREAM_AUTH]: 'not-base64url-json!!!' } },
    )
    expect(garbage.status).toBe(400)

    const noKey = base64urlEncode(
      new TextEncoder().encode(JSON.stringify({ email: 'a@service.bytebase.com' })),
    )
    const partial = await envelope('List', {}, { headers: { [HEADER_TB_UPSTREAM_AUTH]: noKey } })
    expect(partial.status).toBe(400)
    expect(((await partial.json()) as { message: string }).message).toContain('service_key')
  })

  it('service_key 不对 → 换发失败 503(不重试放大,避免触发登录锁定)', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope(
      'List',
      {},
      { headers: { [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(undefined, 'bbs_wrong') } },
    )
    expect(res.status).toBe(503)
    expect(((await res.json()) as { message: string }).message).toContain('service_key')
    expect(upstream.loginCalls()).toBe(1)
  })

  it('错 service_key 不得蹭同 email 的有效缓存令牌(缓存键含 key 摘要;2026-07-29 生产实测回归)', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    // 先用正确 key 换发并缓存。
    expect((await envelope('List', {})).status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    // 同 email、错 key:若缓存键漏了 key 摘要,这里会命中缓存回 200(泄漏 PLUGIN_TOKEN +
    // 猜到 SA 邮箱即可白蹭令牌,且 key 轮换在旧令牌到期前不生效)。
    const res = await envelope(
      'List',
      {},
      { headers: { [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(undefined, 'bbs_wrong') } },
    )
    expect(res.status).toBe(503)
    expect(upstream.loginCalls()).toBe(2) // 确实去打了 login 而非读缓存
  })
})

describe('List / Get / Call(访问令牌自动换发)', () => {
  it('List:换发一次令牌,ToolSpec 按名兜底 effect(上游不带 annotations);二次调用复用缓存不再换发', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const first = await envelope('List', {})
    expect(first.status).toBe(200)
    const specs = (await first.json()) as Array<{ effect?: string, name: string }>
    expect(specs.map(s => s.name).sort()).toEqual([
      'get_schema',
      'propose_database_change',
      'query_database',
    ])
    expect(specs.find(s => s.name === 'query_database')?.effect).toBe('read')
    expect(specs.find(s => s.name === 'propose_database_change')?.effect).toBe('destructive')
    expect(upstream.loginCalls()).toBe(1)

    const second = await envelope('List', {})
    expect(second.status).toBe(200)
    expect(upstream.loginCalls()).toBe(1) // token 缓存余量充足(exp +1h),不再换发
  })

  it('Get:按名取 spec;未知名 → 404', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const got = await envelope('Get', { name: 'get_schema' })
    expect(got.status).toBe(200)
    expect(((await got.json()) as { name: string }).name).toBe('get_schema')

    const missing = await envelope('Get', { name: 'nope' })
    expect(missing.status).toBe(404)
  })

  it('Call:结果 ToolResult 原样返回;同 X-TB-Request-Id 重放幂等(不重复打上游)', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const requestId = crypto.randomUUID()
    const call = await envelope(
      'Call',
      { name: 'query_database', args: { database: 'db', statement: 'SELECT 1' } },
      { headers: { 'x-tb-request-id': requestId } },
    )
    expect(call.status).toBe(200)
    const result = (await call.json()) as { content: Array<{ text: string }> }
    expect(result.content[0]?.text).toBe(
      'bytebase:query_database:{"database":"db","statement":"SELECT 1"}',
    )

    const callsBefore = upstream.fetchMock.mock.calls.length
    const replay = await envelope(
      'Call',
      { name: 'query_database', args: { database: 'db', statement: 'SELECT 1' } },
      { headers: { 'x-tb-request-id': requestId } },
    )
    expect(replay.status).toBe(200)
    expect(upstream.fetchMock.mock.calls.length).toBe(callsBefore) // 重放,零上游请求
  })

  it('令牌失效(上游 401)→ 强制重换发一次后成功;换发计数 +1', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    expect((await envelope('List', {})).status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    upstream.revokeAllTokens()

    // 缓存令牌仍在余量内但已失效(service_key 轮换/SA 停用):401 → 强制重换发 → 重试成功。
    const after = await envelope('List', {})
    expect(after.status).toBe(200)
    const specs = (await after.json()) as Array<{ name: string }>
    expect(specs.map(s => s.name)).toContain('query_database')
    expect(upstream.loginCalls()).toBe(2)
  })

  it('会话内令牌过期(HTTP 200 + 文本 access token expired)→ 丢会话 + 重换发 + 重握手自愈(2026-07-29 生产实测回归)', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    // 建会话并成功调一次(会话绑住当前 token)。
    const first = await envelope('Call', { name: 'query_database', args: { q: 1 } })
    expect(first.status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    // 生产序列:①会话里绑的 token 到期失效;②时钟越过刷新余量,plugin 自行换发新令牌
    // 进请求头。于是"头有效 + 会话绑的已失效" —— 上游不回 401(头是好的),而是
    // 200 + "access token expired"。只换令牌没用,新令牌进不了旧会话,必须连会话一起丢。
    upstream.expireSessionBoundTokens()
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.setSystemTime(Date.now() + 58 * 60_000) // 越过 5min 刷新余量(令牌 1h)
    try {
      const healed = await envelope('Call', { name: 'query_database', args: { q: 2 } })
      expect(healed.status).toBe(200)
      const result = (await healed.json()) as { content: Array<{ text: string }> }
      // 自愈后拿到真实结果,而不是过期错误。
      expect(result.content[0]?.text).toContain('bytebase:query_database')
      expect(result.content[0]?.text).not.toContain('access token expired')
      expect(upstream.loginCalls()).toBeGreaterThanOrEqual(2) // 确实重换发了
    } finally {
      vi.useRealTimers()
    }
  })

  it('会话过期(有效令牌 + 陈旧 sessionId → 404)→ 清会话完整重握手,不重换发令牌', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    expect((await envelope('List', {})).status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    upstream.expireSessions()

    const after = await envelope('List', {})
    expect(after.status).toBe(200)
    expect(upstream.loginCalls()).toBe(1) // 会话层失效与凭证层无关,不触发换发
  })
})

describe('白名单双闸(List 过滤 + Call 拒绝)', () => {
  it('配了 BYTEBASE_ALLOWED_TOOLS:List 只宣告白名单内;白名单外即使知道名字也 Call 不动', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)
    ;(env as { BYTEBASE_ALLOWED_TOOLS: string }).BYTEBASE_ALLOWED_TOOLS
      = 'query_database,get_schema'

    const list = await envelope('List', {})
    const specs = (await list.json()) as Array<{ name: string }>
    expect(specs.map(s => s.name).sort()).toEqual(['get_schema', 'query_database'])

    const denied = await envelope('Call', { name: 'propose_database_change', args: {} })
    expect(denied.status).toBe(403)
    expect(((await denied.json()) as { code: string }).code).toBe('permission_denied')

    const allowed = await envelope('Call', { name: 'query_database', args: { q: 1 } })
    expect(allowed.status).toBe(200)
  })
})

describe('多实例 / 多账号(缓存键控 baseUrl|email)', () => {
  it('不同凭证各自换发令牌,缓存不串号;各自二次调用均命中自己缓存', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const other = { [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth('other@service.bytebase.com') }

    expect((await envelope('List', {})).status).toBe(200) // 账号 A
    expect((await envelope('List', {}, { headers: other })).status).toBe(200) // 账号 B:自己换发
    expect(upstream.loginCalls()).toBe(2)

    expect((await envelope('List', {})).status).toBe(200)
    expect((await envelope('List', {}, { headers: other })).status).toBe(200)
    expect(upstream.loginCalls()).toBe(2) // 各自命中缓存,无新增换发
  })

  it('凭证内 base_url 覆盖 env(多实例挂载);env 与凭证皆缺 base_url → 503', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    // 凭证显式带 base_url(带尾斜杠,验证归一化)→ 仍打到同一 mock 实例。
    const withBase = {
      [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(undefined, SERVICE_KEY, `${BASE_URL}/`),
    }
    expect((await envelope('List', {}, { headers: withBase })).status).toBe(200)

    const saved = (env as { BYTEBASE_BASE_URL: string }).BYTEBASE_BASE_URL
    ;(env as { BYTEBASE_BASE_URL: string }).BYTEBASE_BASE_URL = ''
    try {
      const res = await envelope('List', {})
      expect(res.status).toBe(503)
      expect(((await res.json()) as { message: string }).message).toContain('base_url')
    } finally {
      ;(env as { BYTEBASE_BASE_URL: string }).BYTEBASE_BASE_URL = saved
    }
  })
})

describe('decodeExp(令牌到期解析)', () => {
  it('取 JWT exp(秒→毫秒);非 JWT / 坏载荷 → undefined(调用方回落保守 TTL)', () => {
    const expMs = 1_800_000_000_000
    expect(decodeExp(fakeJwt('sa@service.bytebase.com', expMs, 1))).toBe(
      Math.floor(expMs / 1000) * 1000,
    )
    expect(decodeExp('opaque-token')).toBeUndefined()
    expect(decodeExp('a.!!!not-base64!!!.c')).toBeUndefined()
  })
})
