import { afterEach, describe, expect, it, vi } from 'vitest'
import { SELF } from 'cloudflare:test'
import {
  FEISHU_HANDOFF_COOKIE,
  FEISHU_HANDOFF_PATH,
  FEISHU_LOGIN_STATUS_PATH,
  newLoginHandoff,
} from '../src/feishuLogin'
import { TEST_ADMIN_SK, TEST_ENCRYPTION_KEY } from './fixtures'

// Dashboard 集成测试:/ui 静态资源托管与路由次序。
// wrangler.jsonc assets.run_worker_first=true + app.ts 显式转发——断言:
// ① /ui 免认证可加载(登录页前置条件);② SPA 回退仅在 /ui 内生效(深链回 index.html);
// ③ 根 ~help / POST 数据面 / system/* 不被静态资源吞掉;④ GET / 的 Accept 分流(浏览器 302 → /ui/)。

const admin = (extra: RequestInit = {}): RequestInit => ({
  ...extra,
  headers: { authorization: `Bearer ${TEST_ADMIN_SK}`, ...(extra.headers ?? {}) },
})

async function configureFeishuSecret(
  value = '{"app_id":"cli_0123456789abcdef","app_secret":"secret_test"}',
): Promise<void> {
  const configured = await SELF.fetch('https://tb.test/system/secret', {
    method: 'POST',
    ...admin(),
    headers: {
      'authorization': `Bearer ${TEST_ADMIN_SK}`,
      'content-type': 'application/json',
      'accept': 'application/json',
    },
    body: JSON.stringify({
      tool: 'set',
      arguments: {
        name: 'feishu-app',
        value,
      },
    }),
  })
  expect(configured.status).toBe(200)
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('/ui 静态资源(免认证)', () => {
  it('GET /ui/ 无 SK 返回 200 HTML(登录页可加载)', async () => {
    const res = await SELF.fetch('https://tb.test/ui/', { redirect: 'manual' })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/html')
    expect(await res.text()).toContain('<div id="root">')
  })

  it('GET /ui(无尾斜线)302 → /ui/', async () => {
    const res = await SELF.fetch('https://tb.test/ui', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location') ?? '', 'https://tb.test').pathname).toBe('/ui/')
  })

  it('构建产物静态文件(/ui/assets/*)可取回', async () => {
    const html = await (await SELF.fetch('https://tb.test/ui/')).text()
    const m = html.match(/\/ui\/(assets\/[^"']+\.js)/)
    expect(m).not.toBeNull()
    const res = await SELF.fetch(`https://tb.test/ui/${m?.[1]}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('javascript')
  })

  it('SPA 深链(/ui/nodes/a/b)回退 index.html', async () => {
    const res = await SELF.fetch('https://tb.test/ui/nodes/a/b')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/html')
    expect(await res.text()).toContain('<div id="root">')
  })
})

describe('Dashboard 飞书登录交接(免 SK、同源限定)', () => {
  it('公开状态端点只返回 enabled,不暴露凭证配置', async () => {
    await configureFeishuSecret()

    const res = await SELF.fetch(`https://tb.test${FEISHU_LOGIN_STATUS_PATH}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toContain('no-store')
    expect(await res.json()).toEqual({ enabled: true })
  })

  it('占位 app_id 不启用登录入口，避免点击后才由飞书返回 20028', async () => {
    await configureFeishuSecret(
      '{"app_id":"cli_local_visual_check","app_secret":"secret_test"}',
    )

    const res = await SELF.fetch(`https://tb.test${FEISHU_LOGIN_STATUS_PATH}`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ enabled: false })
  })

  it('Dashboard OAuth 回调不在 URL 暴露 SK,交接后新 SK 可直接访问网关', async () => {
    await configureFeishuSecret()
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(String(input))
      const url = new URL(request.url)
      if (url.pathname === '/open-apis/authen/v2/oauth/token') {
        return Response.json({ access_token: 'user-token-test' })
      }
      if (url.pathname === '/open-apis/authen/v1/user_info') {
        return Response.json({ code: 0, data: { open_id: 'ou_dashboard_test', name: '飞书用户' } })
      }
      return new Response('unexpected upstream', { status: 500 })
    }))

    const start = await SELF.fetch('https://tb.test/login?continue=%2Fui%2F', {
      redirect: 'manual',
    })
    expect(start.status).toBe(302)
    const authorizeUrl = new URL(start.headers.get('location') ?? '')
    expect(authorizeUrl.origin).toBe('https://open.feishu.cn')
    expect(authorizeUrl.searchParams.get('redirect_uri')).toBe(
      'https://tool-bridge.fantacy.live/~feishu/callback',
    )
    const state = authorizeUrl.searchParams.get('state')
    expect(state).toBeTruthy()

    const callback = await SELF.fetch(
      `https://tb.test/~feishu/callback?code=code-ok&state=${encodeURIComponent(state ?? '')}`,
      { redirect: 'manual' },
    )
    expect(callback.status).toBe(302)
    expect(callback.headers.get('location')).toBe('/ui/?login=feishu')
    expect(callback.headers.get('location')).not.toContain('tbk_')
    const setCookie = callback.headers.get('set-cookie') ?? ''
    expect(setCookie).toContain(`${FEISHU_HANDOFF_COOKIE}=`)
    expect(setCookie).toContain('HttpOnly')
    expect(setCookie).toContain('SameSite=Strict')
    expect(setCookie).not.toContain('tbk_')
    const cookie = setCookie.split(';', 1)[0]
    expect(cookie).toBeDefined()
    if (cookie === undefined) throw new Error('missing handoff cookie')

    const handoff = await SELF.fetch(`https://tb.test${FEISHU_HANDOFF_PATH}`, {
      method: 'POST',
      headers: { origin: 'https://tb.test', cookie },
    })
    expect(handoff.status).toBe(200)
    const profile = (await handoff.json()) as { sk: string }
    expect(profile.sk).toMatch(/^tbk_/)

    const help = await SELF.fetch('https://tb.test/~help', {
      headers: { authorization: `Bearer ${profile.sk}` },
    })
    expect(help.status).toBe(200)
  })

  it('同源 POST 消费短时 HttpOnly Cookie,返回 SK 后立即清 Cookie', async () => {
    const secret = 'tbk_dashboard_handoff_test'
    const handoff = await newLoginHandoff(
      { baseUrl: 'https://tb.test', secret, name: '飞书用户' },
      TEST_ENCRYPTION_KEY,
      Date.now(),
    )
    expect(handoff).not.toContain(secret)

    const res = await SELF.fetch(`https://tb.test${FEISHU_HANDOFF_PATH}`, {
      method: 'POST',
      headers: {
        origin: 'https://tb.test',
        cookie: `${FEISHU_HANDOFF_COOKIE}=${handoff}`,
      },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toContain('no-store')
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0')
    expect(await res.json()).toEqual({
      baseUrl: 'https://tb.test',
      sk: secret,
      profile: 'feishu',
      userName: '飞书用户',
    })
  })

  it('缺 Cookie 或非同源 Origin 一律拒绝且清交接 Cookie', async () => {
    const missing = await SELF.fetch(`https://tb.test${FEISHU_HANDOFF_PATH}`, {
      method: 'POST',
      headers: { origin: 'https://tb.test' },
    })
    expect(missing.status).toBe(401)
    expect(missing.headers.get('set-cookie')).toContain('Max-Age=0')

    const crossSite = await SELF.fetch(`https://tb.test${FEISHU_HANDOFF_PATH}`, {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
    })
    expect(crossSite.status).toBe(403)
    expect(crossSite.headers.get('set-cookie')).toContain('Max-Age=0')
  })
})

describe('路由次序:Worker 逻辑不被 assets 吞', () => {
  it('根 ~help(带 SK)仍由 Worker 返回帮助(默认 markdown)', async () => {
    const res = await SELF.fetch('https://tb.test/~help', admin())
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/markdown')
    expect(await res.text()).toContain('HTBP')
  })

  it('浏览器形态的 GET /~help(Accept: text/html)也不落入 SPA 回退', async () => {
    const res = await SELF.fetch('https://tb.test/~help', {
      ...admin(),
      headers: { authorization: `Bearer ${TEST_ADMIN_SK}`, accept: 'text/html' },
      redirect: 'manual',
    })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('HTBP')
  })

  it('POST /system/status 数据面正常(不被静态回退拦截)', async () => {
    const res = await SELF.fetch('https://tb.test/system/status', {
      method: 'POST',
      ...admin(),
      headers: {
        'authorization': `Bearer ${TEST_ADMIN_SK}`,
        'content-type': 'application/json',
        'accept': 'application/json',
      },
      body: JSON.stringify({ tool: 'get', arguments: {} }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { healthy: boolean }
    expect(body.healthy).toBe(true)
  })

  it('无 SK 的 API 请求仍 401(认证面未被 /ui 例外扩大)', async () => {
    const res = await SELF.fetch('https://tb.test/~tree')
    expect(res.status).toBe(401)
  })
})

describe('GET / 的 Accept 分流', () => {
  it('Accept: text/html → 302 /ui/(免认证,浏览器直开)', async () => {
    const res = await SELF.fetch('https://tb.test/', {
      headers: { accept: 'text/html,application/xhtml+xml' },
      redirect: 'manual',
    })
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location') ?? '', 'https://tb.test').pathname).toBe('/ui/')
  })

  it('非 HTML Accept 无 SK → 401(原语义不变)', async () => {
    const res = await SELF.fetch('https://tb.test/', { redirect: 'manual' })
    expect(res.status).toBe(401)
  })

  it('非 HTML Accept 带 SK → 404 no such path(原语义不变)', async () => {
    const res = await SELF.fetch('https://tb.test/', { ...admin(), redirect: 'manual' })
    expect(res.status).toBe(404)
  })
})
