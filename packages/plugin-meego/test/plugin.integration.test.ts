import {
  base64urlEncode,
  encodeCallContext,
  HEADER_TB_CONTEXT,
  HEADER_TB_UPSTREAM_AUTH,
} from '@tool-bridge/core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SELF } from 'cloudflare:test'
import { clearPatCache } from '../src/pat'

// plugin-meego 集成测试:契约面 / envelope 鉴权 / 凭证经 X-TB-Upstream-Auth 传入 /
// **操作人身份按 keyId 从 mountConfig.userKeys 解析**(核心行为)/ PAT 换发缓存 /
// 鉴权失效强制重换发。Meego open_api 全部 fetch mock,默认离线确定性。

const BASE = 'https://meego-api.mock'
const PLUGIN_TOKEN = 'tbp_test_token'
const PROJECT_KEY = '6a4226868b7eed94090347eb'

/** 平台注入形态:base64url JSON {plugin_id,plugin_secret}。 */
function upstreamAuth(pluginId = 'MII_test_plugin', pluginSecret = 'test_secret'): string {
  return base64urlEncode(
    new TextEncoder().encode(JSON.stringify({ plugin_id: pluginId, plugin_secret: pluginSecret })),
  )
}

/** X-TB-Context:keyId + 挂载 providerConfig(userKeys 映射)。 */
function tbContext(keyId: string, userKeys?: Record<string, string>): string {
  return encodeCallContext({
    keyId,
    owner: 'user:test',
    scopes: [{ pattern: '**', actions: ['call'] }],
    traceId: 'trace-test',
    mountPath: 'mcp/meego2',
    ...(userKeys !== undefined ? { mountConfig: { userKeys } } : {}),
  })
}

/**
 * Meego open_api mock:plugin_token 换发(签发递增 token)+ comment/create(校验
 * X-PLUGIN-TOKEN ∈ 有效集,记录 X-USER-KEY)+ user/query。`revokeAllTokens()` 模拟
 * PAT 被吊销:老 token 一律 err_msg 'token expired'。
 */
function meegoMock() {
  const validTokens = new Set<string>()
  let tokenSeq = 0
  let authCalls = 0
  const commentCalls: Array<{ path: string, userKey: string | null }> = []

  const ok = (data: unknown, extra: Record<string, unknown> = {}) =>
    new Response(JSON.stringify({ err_code: 0, err_msg: '', data, ...extra }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input))
    if (url.origin !== BASE) return new Response('unexpected upstream', { status: 500 })

    if (url.pathname === '/open_api/authen/plugin_token') {
      authCalls += 1
      const body = JSON.parse(String(init?.body)) as {
        plugin_id?: string
        plugin_secret?: string
        type?: number
      }
      if (!body.plugin_id || body.plugin_secret !== 'test_secret' || body.type !== 0) {
        return new Response(
          JSON.stringify({ error: { code: 10003, msg: 'invalid plugin credential' } }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        )
      }
      tokenSeq += 1
      const token = `pat-${body.plugin_id}-${tokenSeq}`
      validTokens.add(token)
      return new Response(
        JSON.stringify({ error: { code: 0, msg: '' }, data: { token, expire_time: 7200 } }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }

    const headers = new Headers(init?.headers)
    const pat = headers.get('X-PLUGIN-TOKEN')
    if (pat === null || !validTokens.has(pat)) {
      return new Response(
        JSON.stringify({ err_code: 10009, err_msg: 'plugin token expired or invalid' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }

    if (url.pathname.endsWith('/comment/create')) {
      commentCalls.push({ path: url.pathname, userKey: headers.get('X-USER-KEY') })
      return ok(9527)
    }
    if (url.pathname.endsWith('/comments')) {
      return ok(
        [{ id: 9527, operator: headers.get('X-USER-KEY'), content: 'hi' }],
        { pagination: { page_num: 1, page_size: 50, total: 1 } },
      )
    }
    if (url.pathname === '/open_api/user/query') {
      const body = JSON.parse(String(init?.body)) as { emails?: string[], user_keys?: string[] }
      const keys = body.user_keys ?? (body.emails ?? []).map(e => `key-of-${e}`)
      return ok(keys.map(k => ({ user_key: k, name_cn: `用户${k}`, email: `${k}@x.com` })))
    }
    return new Response('no such mock path', { status: 404 })
  })

  return {
    fetchMock,
    authCalls: () => authCalls,
    commentCalls,
    revokeAllTokens: () => validTokens.clear(),
  }
}

const USER_KEYS = { 'key-alice': 'uk_alice_001', 'key-bob': 'uk_bob_002' }

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
      [HEADER_TB_CONTEXT]: tbContext('key-alice', USER_KEYS),
      ...(init.headers ?? {}),
    },
    body: JSON.stringify({ tool, arguments: args }),
  })
}

function addCommentArgs(content = 'looks good'): Record<string, unknown> {
  return {
    name: 'add_comment',
    args: {
      project_key: PROJECT_KEY,
      work_item_type_key: 'issue',
      work_item_id: 4321,
      content,
    },
  }
}

beforeEach(() => {
  clearPatCache()
})

describe('契约面(生命周期 GET,不鉴权)', () => {
  it('healthz / ~describe / ~help 形状符合 tool-provider/v1', async () => {
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
  })
})

describe('envelope 鉴权与上下文', () => {
  it('无 / 错 Bearer → 401', async () => {
    const none = await envelope('List', {}, { headers: { authorization: '' } })
    expect(none.status).toBe(401)
    const bad = await envelope('List', {}, { headers: { authorization: 'Bearer wrong' } })
    expect(bad.status).toBe(401)
  })

  it('缺 X-TB-Context → 400(操作人解析依赖 CallContext)', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)
    const res = await envelope('Call', addCommentArgs(), {
      headers: { [HEADER_TB_CONTEXT]: '' },
    })
    expect(res.status).toBe(400)
  })

  it('缺 X-TB-Upstream-Auth → 503(挂载缺 authRef 是配置错误)', async () => {
    const res = await envelope('Call', addCommentArgs(), {
      headers: { [HEADER_TB_UPSTREAM_AUTH]: '' },
    })
    expect(res.status).toBe(503)
  })
})

describe('List / Get', () => {
  it('List 返回四工具;add_comment 标 destructive、list_comments 标 read', async () => {
    const res = await envelope('List', {})
    expect(res.status).toBe(200)
    const tools = (await res.json()) as Array<{ effect?: string, name: string }>
    expect(tools.map(t => t.name).sort()).toEqual([
      'add_comment',
      'list_comments',
      'query_user',
      'whoami',
    ])
    expect(tools.find(t => t.name === 'add_comment')?.effect).toBe('destructive')
    expect(tools.find(t => t.name === 'list_comments')?.effect).toBe('read')
  })

  it('Get 未知工具 → 404', async () => {
    const res = await envelope('Get', { name: 'nope' })
    expect(res.status).toBe(404)
  })
})

describe('操作人身份(核心行为)', () => {
  it('add_comment 以调用方绑定的 user_key 落地 X-USER-KEY', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', addCommentArgs())
    expect(res.status).toBe(200)
    const body = (await res.json()) as { content: { comment_id: number } }
    expect(body.content.comment_id).toBe(9527)
    expect(upstream.commentCalls).toHaveLength(1)
    expect(upstream.commentCalls[0]?.userKey).toBe('uk_alice_001')
    expect(upstream.commentCalls[0]?.path).toBe(
      `/open_api/${PROJECT_KEY}/work_item/issue/4321/comment/create`,
    )
  })

  it('不同 keyId → 不同 X-USER-KEY(同一挂载多身份)', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', addCommentArgs(), {
      headers: { [HEADER_TB_CONTEXT]: tbContext('key-bob', USER_KEYS) },
    })
    expect(res.status).toBe(200)
    expect(upstream.commentCalls[0]?.userKey).toBe('uk_bob_002')
  })

  it('keyId 未绑定 → 403 permission_denied,不回落默认身份、零上游请求', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', addCommentArgs(), {
      headers: { [HEADER_TB_CONTEXT]: tbContext('key-stranger', USER_KEYS) },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as { code: string, message: string }
    expect(body.code).toBe('permission_denied')
    expect(body.message).toContain('key-stranger')
    expect(upstream.commentCalls).toHaveLength(0)
    expect(upstream.authCalls()).toBe(0)
  })

  it('mountConfig 整体缺失(挂载没配 userKeys)→ 403', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', addCommentArgs(), {
      headers: { [HEADER_TB_CONTEXT]: tbContext('key-alice') },
    })
    expect(res.status).toBe(403)
  })

  it('whoami 返回绑定身份与用户详情', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', { name: 'whoami', args: {} })
    expect(res.status).toBe(200)
    const body = (await res.json()) as {
      content: { key_id: string, user_key: string, users: Array<{ user_key: string }> }
    }
    expect(body.content.key_id).toBe('key-alice')
    expect(body.content.user_key).toBe('uk_alice_001')
    expect(body.content.users[0]?.user_key).toBe('uk_alice_001')
  })
})

describe('PAT 换发缓存与失效重试', () => {
  it('同 plugin_id 连续调用只换发一次;PAT 吊销后强制重换发重试成功', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    await envelope('Call', addCommentArgs('one'))
    await envelope('Call', addCommentArgs('two'))
    expect(upstream.authCalls()).toBe(1) // 第二次走缓存

    upstream.revokeAllTokens()
    const res = await envelope('Call', addCommentArgs('three'))
    expect(res.status).toBe(200) // err_msg 'token expired' → 强制重换发重试
    expect(upstream.authCalls()).toBe(2)
    expect(upstream.commentCalls).toHaveLength(3)
  })

  it('凭证坏(换发失败)→ 503', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', addCommentArgs(), {
      headers: { [HEADER_TB_UPSTREAM_AUTH]: upstreamAuth('MII_test_plugin', 'wrong_secret') },
    })
    expect(res.status).toBe(503)
  })
})

describe('query_user / list_comments', () => {
  it('query_user 按邮箱反查 user_key(绑定新同学的入口)', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', {
      name: 'query_user',
      args: { emails: ['carol@corp.com'] },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { content: { users: Array<{ user_key: string }> } }
    expect(body.content.users[0]?.user_key).toBe('key-of-carol@corp.com')
  })

  it('query_user 两参数全缺 → 400', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)
    const res = await envelope('Call', { name: 'query_user', args: {} })
    expect(res.status).toBe(400)
  })

  it('list_comments 透传分页并返回 operator', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const res = await envelope('Call', {
      name: 'list_comments',
      args: {
        project_key: PROJECT_KEY,
        work_item_type_key: 'issue',
        work_item_id: 4321,
        page_num: 1,
        page_size: 10,
      },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as {
      content: { comments: Array<{ operator: string }>, pagination: { total: number } }
    }
    expect(body.content.comments[0]?.operator).toBe('uk_alice_001')
    expect(body.content.pagination.total).toBe(1)
  })
})

describe('幂等去重', () => {
  it('同 X-TB-Request-Id 重放不重复评论', async () => {
    const upstream = meegoMock()
    vi.stubGlobal('fetch', upstream.fetchMock)

    const requestId = crypto.randomUUID()
    const first = await envelope('Call', addCommentArgs(), {
      headers: { 'x-tb-request-id': requestId },
    })
    expect(first.status).toBe(200)
    const replay = await envelope('Call', addCommentArgs(), {
      headers: { 'x-tb-request-id': requestId },
    })
    expect(replay.status).toBe(200)
    expect(upstream.commentCalls).toHaveLength(1) // 重放,零上游请求
  })
})
