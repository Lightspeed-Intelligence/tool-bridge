import {
  identify,
  MemoryStateStore,
  SecretStoreImpl,
} from '@tool-bridge/core'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  createTbApp,
  type OAuthDelegationClient,
  runBootstrap,
  type TbAppDeps,
} from '../src/index'
import { TEST_ADMIN_SK, TEST_ENCRYPTION_KEY } from './fixtures'
import { TEST_REMOTE, TEST_VERSION } from './harness'

const CLIENT_SECRET = 'tcode-oauth-client-secret-000000000000'
const CLIENT_ID = 'tcode'
const REDIRECT_URI = 'https://tcode.example.com/api/v1/integrations/tool-bridge/callback'
const VERIFIER = 'tcode_pkce_verifier_000000000000000000000000000000000000000000000000'

const client: OAuthDelegationClient = {
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUris: [REDIRECT_URI],
  accessTokenTtlSeconds: 300,
  refreshTokenTtlSeconds: 3_600,
  grants: [
    {
      name: 'database_production_read',
      description: 'Read production diagnostics through the approved database tool',
      scopes: [
        { pattern: 'plugins/bytebase', actions: ['read', 'call'] },
        { pattern: 'plugins/bytebase/**', actions: ['read', 'call'] },
      ],
    },
    {
      name: 'database_test_write',
      description: 'Use the approved test database tool',
      scopes: [
        { pattern: 'plugins/bytebase-rw', actions: ['read', 'call'] },
        { pattern: 'plugins/bytebase-rw/**', actions: ['read', 'call'] },
      ],
    },
  ],
}

async function createDelegationApp() {
  const state = new MemoryStateStore()
  await runBootstrap(state, { adminSk: TEST_ADMIN_SK, requireAdminSk: true })
  const secrets = new SecretStoreImpl(state, TEST_ENCRYPTION_KEY)
  await secrets.set(
    'feishu-app',
    JSON.stringify({ app_id: 'cli_0123456789abcdef', app_secret: 'feishu-secret' }),
    new Date().toISOString(),
  )
  const deps: TbAppDeps = {
    allowInsecureHttp: false,
    canonicalOrigin: 'https://tb.example.com',
    encryptionKey: TEST_ENCRYPTION_KEY,
    feishuLoginSecretRef: 'feishu-app',
    oauthDelegationClients: [client],
    remote: TEST_REMOTE,
    secrets,
    state,
    version: TEST_VERSION,
  }
  const app = createTbApp(deps)
  return {
    request: async (input: RequestInfo | URL, init?: RequestInit) =>
      await app.request(input as never, init),
    state,
  }
}

function feishuMock() {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(String(input), init)
    const url = new URL(request.url)
    if (request.method === 'POST' && url.pathname === '/open-apis/authen/v2/oauth/token') {
      return Response.json({ access_token: 'feishu-user-token' })
    }
    if (request.method === 'GET' && url.pathname === '/open-apis/authen/v1/user_info') {
      return Response.json({ code: 0, data: { open_id: 'ou_requester', name: '张三' } })
    }
    return new Response('unexpected upstream request', { status: 500 })
  })
}

async function challenge(verifier: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  return Buffer.from(bytes).toString('base64url')
}

function basicAuth(): string {
  return `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`
}

async function authorize(
  request: Awaited<ReturnType<typeof createDelegationApp>>['request'],
  grant = 'database_production_read',
) {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: grant,
    state: 'tcode-state-0001',
    code_challenge: await challenge(VERIFIER),
    code_challenge_method: 'S256',
  })
  const start = await request(`https://tb.example.com/oauth/authorize?${query}`)
  expect(start.status, await start.clone().text()).toBe(302)
  const feishu = new URL(start.headers.get('location')!)
  expect(feishu.origin).toBe('https://open.feishu.cn')
  expect(feishu.searchParams.get('redirect_uri')).toBe(
    'https://tb.example.com/~feishu/callback',
  )

  const callback = await request(
    `https://tb.example.com/~feishu/callback?code=feishu-code&state=${encodeURIComponent(feishu.searchParams.get('state')!)}`,
  )
  expect(callback.status).toBe(302)
  const redirect = new URL(callback.headers.get('location')!)
  expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT_URI)
  expect(redirect.searchParams.get('state')).toBe('tcode-state-0001')
  expect(redirect.searchParams.get('code')).toMatch(/^tbc_/)
  return redirect.searchParams.get('code')!
}

async function exchangeCode(
  request: Awaited<ReturnType<typeof createDelegationApp>>['request'],
  code: string,
) {
  return await request('https://tb.example.com/oauth/token', {
    method: 'POST',
    headers: {
      'authorization': basicAuth(),
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
    }),
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('OAuth delegation for first-party automation clients', () => {
  it('exchanges a Feishu-authorized, PKCE-bound code for a refresh grant and narrow access SK', async () => {
    const tb = await createDelegationApp()
    vi.stubGlobal('fetch', feishuMock())

    const code = await authorize(tb.request)
    const response = await exchangeCode(tb.request, code)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toContain('no-store')
    const token = (await response.json()) as {
      access_token: string
      expires_in: number
      refresh_expires_in: number
      refresh_token: string
      scope: string
      subject: string
      token_type: string
    }
    expect(token).toMatchObject({
      token_type: 'Bearer',
      expires_in: 300,
      refresh_expires_in: 3_600,
      scope: 'database_production_read',
      subject: 'ou_requester',
    })
    expect(token.access_token).toMatch(/^tbk_/)
    expect(token.refresh_token).toMatch(/^tbr_/)

    const identity = await identify(
      tb.state,
      `Bearer ${token.access_token}`,
      new Date().toISOString(),
    )
    expect(identity).toMatchObject({
      owner: 'user:ou_requester',
      scopes: client.grants[0]!.scopes,
    })

    const replay = await exchangeCode(tb.request, code)
    expect(replay.status).toBe(400)
    expect(await replay.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('refreshes only a subset of the user-approved grants and rejects scope widening', async () => {
    const tb = await createDelegationApp()
    vi.stubGlobal('fetch', feishuMock())
    const code = await authorize(tb.request)
    const first = (await (await exchangeCode(tb.request, code)).json()) as {
      refresh_token: string
    }

    const refresh = (scope: string) =>
      tb.request('https://tb.example.com/oauth/token', {
        method: 'POST',
        headers: {
          'authorization': basicAuth(),
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: first.refresh_token,
          scope,
        }),
      })

    const narrowed = await refresh('database_production_read')
    expect(narrowed.status).toBe(200)
    expect(await narrowed.json()).toMatchObject({ scope: 'database_production_read' })

    const widened = await refresh('database_test_write')
    expect(widened.status).toBe(400)
    expect(await widened.json()).toMatchObject({ error: 'invalid_scope' })
  })

  it('revokes access and refresh tokens without revealing whether unknown tokens exist', async () => {
    const tb = await createDelegationApp()
    vi.stubGlobal('fetch', feishuMock())
    const code = await authorize(tb.request)
    const issued = (await (await exchangeCode(tb.request, code)).json()) as {
      access_token: string
      refresh_token: string
    }

    const revoke = async (token: string) =>
      await tb.request('https://tb.example.com/oauth/revoke', {
        method: 'POST',
        headers: {
          'authorization': basicAuth(),
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ token }),
      })

    expect((await revoke(issued.access_token)).status).toBe(200)
    expect(
      await identify(tb.state, `Bearer ${issued.access_token}`, new Date().toISOString()),
    ).toBeNull()
    expect((await revoke(issued.refresh_token)).status).toBe(200)
    expect((await revoke('tbr_unknown')).status).toBe(200)

    const refreshAfterRevoke = await tb.request('https://tb.example.com/oauth/token', {
      method: 'POST',
      headers: {
        'authorization': basicAuth(),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: issued.refresh_token,
      }),
    })
    expect(refreshAfterRevoke.status).toBe(400)
    expect(await refreshAfterRevoke.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('fails closed for unregistered redirects, grants, client secrets, and PKCE verifiers', async () => {
    const tb = await createDelegationApp()
    vi.stubGlobal('fetch', feishuMock())

    const invalidRedirect = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: 'https://evil.example.com/callback',
      scope: 'database_production_read',
      state: 'state',
      code_challenge: await challenge(VERIFIER),
      code_challenge_method: 'S256',
    })
    expect(
      (await tb.request(`https://tb.example.com/oauth/authorize?${invalidRedirect}`)).status,
    ).toBe(400)

    const invalidGrant = new URLSearchParams(invalidRedirect)
    invalidGrant.set('redirect_uri', REDIRECT_URI)
    invalidGrant.set('scope', 'system_admin')
    expect((await tb.request(`https://tb.example.com/oauth/authorize?${invalidGrant}`)).status).toBe(
      400,
    )

    const code = await authorize(tb.request)
    const badVerifier = await tb.request('https://tb.example.com/oauth/token', {
      method: 'POST',
      headers: {
        'authorization': basicAuth(),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: `${VERIFIER}x`,
      }),
    })
    expect(badVerifier.status).toBe(400)
    expect(await badVerifier.json()).toMatchObject({ error: 'invalid_grant' })

    const badSecret = await tb.request('https://tb.example.com/oauth/token', {
      method: 'POST',
      headers: {
        'authorization': `Basic ${Buffer.from(`${CLIENT_ID}:wrong-secret`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code }),
    })
    expect(badSecret.status).toBe(401)
    expect(await badSecret.json()).toMatchObject({ error: 'invalid_client' })
  })
})
