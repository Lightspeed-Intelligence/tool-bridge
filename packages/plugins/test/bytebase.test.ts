import {
  base64urlEncode,
  type CallContext,
  encodeCallContext,
  HEADER_TB_CONTEXT,
  HEADER_TB_UPSTREAM_AUTH,
} from '@tool-bridge/core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { clearTokenCache, decodeExp } from '../src/bytebase/token'
import { clearSessionCache } from '../src/bytebase/bytebaseMcp'
import { createBytebasePlugin } from '../src/bytebase/index'

/**
 * 原 plugin-bytebase 的 workerd(vitest-pool-workers)集成测试,随"内置插件 = 单包源码
 * 文件夹"重构移植为纯 Node vitest:SELF.fetch 换成直调 plugin.fetch(同一 fetch 契约),
 * miniflare bindings 换成显式 ENV 对象。断言原样保留 —— 重构没有偷偷改契约。
 *
 * 协议面(健康检查 / ~describe / ~help / envelope / 鉴权 / 去重 / 凭证解包)现由
 * @tool-bridge/plugin-sdk 提供(plugin/v2,不再是旧的 tool-provider/v1);业务面(SA 访问
 * 令牌换发缓存、上游 401 强制重换发、白名单双闸、多实例不串号)照旧断言。
 */
const BASE_URL = 'https://bytebase.mock'
const LOGIN_URL = `${BASE_URL}/v1/auth/login`
const MCP_URL = `${BASE_URL}/mcp`
const PLUGIN_TOKEN = 'tbp_test_token'
const SERVICE_KEY = 'bbs_test_key'

const ENV = {
  PLUGIN_TOKEN,
  BYTEBASE_BASE_URL: BASE_URL,
  BYTEBASE_ALLOWED_TOOLS: '',
}
const plugin = createBytebasePlugin()
const SELF = {
  fetch: (url: string, init?: RequestInit): Promise<Response> =>
    Promise.resolve(plugin.fetch(new Request(url, init), ENV as never)),
}

/** 平台随每次调用下发的 CallContext(SDK 要求 X-TB-Context 必带)。 */
const CALLER: CallContext = {
  keyId: 'k1',
  owner: 'agent:tester',
  scopes: [],
  traceId: 't1',
  mountPath: 'bytebase',
  exportId: 'actions',
}

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
  const b64 = (o: unknown): string => base64urlEncode(new TextEncoder().encode(JSON.stringify(o)))
  return [
    b64({ alg: 'HS256', kid: 'v1', typ: 'JWT' }),
    b64({ aud: ['bb.user.access'], exp: Math.floor(expMs / 1000), iss: 'bytebase', sub }),
    `sig-${seq}`,
  ].join('.')
}

/**
 * Bytebase 侧 mock:login(签发递增 JWT,exp = 现在 +1h)+ Streamable HTTP MCP 上游
 * (校验 Bearer ∈ 有效集,否则 401;陈旧 sessionId → 404)。`revokeAllTokens()` 模拟
 * service_key 轮换/SA 停用:老 token 请求一律 401。
 */
function bytebaseMock(tools: Array<{ description: string, name: string }>) {
  const validTokens = new Set<string>()
  const sessions = new Set<string>()
  let tokenSeq = 0
  let sessionSeq = 0
  let loginCalls = 0

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    const url = new URL(request.url)

    if (url.href === LOGIN_URL) {
      loginCalls += 1
      const body = (await request.json()) as { email?: string, password?: string, web?: boolean }
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
      const auth = request.headers.get('authorization') ?? ''
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
      const body = (await request.json()) as {
        id?: number | string
        method: string
        params?: { arguments?: unknown, name?: string, protocolVersion?: string }
      }
      const sid = request.headers.get('mcp-session-id')
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
        // Bytebase 3.19.0 实测只发 name/description/inputSchema,不带 annotations
        // ——plugin 须按工具名兜底 effect。
        return rpc({ tools: tools.map(t => ({ ...t, inputSchema: { type: 'object' } })) })
      }
      if (body.method === 'tools/call') {
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
      [HEADER_TB_CONTEXT]: encodeCallContext(CALLER),
      [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(),
      ...(init.headers ?? {}),
    },
    body: JSON.stringify({ tool, arguments: args }),
  })
}

beforeEach(() => {
  clearTokenCache()
  clearSessionCache()
  ENV.BYTEBASE_ALLOWED_TOOLS = ''
  ENV.BYTEBASE_BASE_URL = BASE_URL
})

describe('契约面(生命周期 GET,不鉴权)', () => {
  it('healthz / ~describe(v2 代理型 export,声明多字段凭证)/ ~help(dynamic)', async () => {
    const health = await SELF.fetch('https://plugin.test/healthz')
    expect(health.status).toBe(200)
    expect(await health.json()).toEqual({ healthy: true })

    const describeRes = await SELF.fetch('https://plugin.test/~describe')
    const described = (await describeRes.json()) as {
      exports: Array<{ credentialFields?: Array<{ key: string }>, id: string, profile: string }>
      protocolVersion: string
    }
    expect(described.protocolVersion).toBe('plugin/v2')
    expect(described.exports[0]?.id).toBe('actions')
    expect(described.exports[0]?.profile).toBe('tools/v1')
    expect(described.exports[0]?.credentialFields?.map(f => f.key)).toEqual([
      'email',
      'service_key',
      'base_url',
    ])

    const helpJson = await SELF.fetch('https://plugin.test/~help')
    expect(await helpJson.json()).toEqual({
      protocolVersion: 'plugin/v2',
      exports: [{ id: 'actions', dynamic: true, cmds: [] }],
    })
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

  it('缺 X-TB-Upstream-Auth → 503(挂载缺 authRef);坏形状 → 400;缺字段 → 400', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const missing = await envelope('List', {}, { headers: { [HEADER_TB_UPSTREAM_AUTH]: '' } })
    expect(missing.status).toBe(503)
    expect(((await missing.json()) as { message: string }).message).toContain('authRef')
    expect(upstream.loginCalls()).toBe(0)

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

  it('错 service_key 不得蹭同 email 的有效缓存令牌(缓存键含 key 摘要)', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    expect((await envelope('List', {})).status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    const res = await envelope(
      'List',
      {},
      { headers: { [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(undefined, 'bbs_wrong') } },
    )
    expect(res.status).toBe(503)
    expect(upstream.loginCalls()).toBe(2)
  })
})

describe('List / Call(访问令牌自动换发)', () => {
  it('List:换发一次令牌,ToolSpec 按名兜底 effect;二次调用复用缓存不再换发', async () => {
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
    expect(upstream.loginCalls()).toBe(1)
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
    expect(upstream.fetchMock.mock.calls.length).toBe(callsBefore)
  })

  it('令牌失效(上游 401)→ 强制重换发一次后成功;换发计数 +1', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    expect((await envelope('List', {})).status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    upstream.revokeAllTokens()

    const after = await envelope('List', {})
    expect(after.status).toBe(200)
    const specs = (await after.json()) as Array<{ name: string }>
    expect(specs.map(s => s.name)).toContain('query_database')
    expect(upstream.loginCalls()).toBe(2)
  })

  it('会话过期(有效令牌 + 陈旧 sessionId → 404)→ 清会话完整重握手,不重换发令牌', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    expect((await envelope('List', {})).status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)

    upstream.expireSessions()

    const after = await envelope('List', {})
    expect(after.status).toBe(200)
    expect(upstream.loginCalls()).toBe(1)
  })
})

describe('白名单双闸(List 过滤 + Call 拒绝)', () => {
  it('配了 BYTEBASE_ALLOWED_TOOLS:List 只宣告白名单内;白名单外即使知道名字也 Call 不动', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)
    ENV.BYTEBASE_ALLOWED_TOOLS = 'query_database,get_schema'

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

    expect((await envelope('List', {})).status).toBe(200)
    expect((await envelope('List', {}, { headers: other })).status).toBe(200)
    expect(upstream.loginCalls()).toBe(2)

    expect((await envelope('List', {})).status).toBe(200)
    expect((await envelope('List', {}, { headers: other })).status).toBe(200)
    expect(upstream.loginCalls()).toBe(2)
  })

  it('凭证内 base_url 覆盖 env(多实例挂载);env 与凭证皆缺 base_url → 503', async () => {
    const upstream = bytebaseMock(TOOLS)
    vi.stubGlobal('fetch', upstream.fetchMock)

    const withBase = {
      [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth(undefined, SERVICE_KEY, `${BASE_URL}/`),
    }
    expect((await envelope('List', {}, { headers: withBase })).status).toBe(200)

    ENV.BYTEBASE_BASE_URL = ''
    const res = await envelope('List', {})
    expect(res.status).toBe(503)
    expect(((await res.json()) as { message: string }).message).toContain('base_url')
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
