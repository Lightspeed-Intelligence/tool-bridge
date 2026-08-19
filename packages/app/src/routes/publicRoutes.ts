/**
 * 树外免认证路由:healthz、`/~ref/<token>` 大对象中转、`/ui` Dashboard 静态资源、
 * 根路径浏览器跳转与 mcp 托管 OAuth 回调。
 *
 * 这些路由必须注册在认证中间件之前:它们各自持有自己的凭证形式(限时签名 token /
 * 加密 state)或本就无凭证(静态资源、健康检查)。
 */
import {
  isTBError,
  type NodeConfig,
  NodeRegistryStore,
  normalizePath,
  SKRegistryStore,
  TBError,
  type TBErrorBody,
  type TreeNode,
} from '@tool-bridge/core'
import { generateCookie, getCookie } from 'hono/cookie'
import type { AppContext, TbAppDeps, TbHono } from '../deps'
import type { RouteEnv } from './env'
import {
  bindMeegoIdentity,
  buildAuthorizeUrl,
  DEFAULT_KEY_TTL_SEC,
  exchangeUserToken,
  FEISHU_CALLBACK_PATH,
  FEISHU_DASHBOARD_PATH,
  FEISHU_HANDOFF_COOKIE,
  FEISHU_HANDOFF_PATH,
  FEISHU_LOGIN_STATUS_PATH,
  feishuAppAccessToken,
  fetchUserInfo,
  HANDOFF_TTL_SEC,
  type MeegoBindDeps,
  newLoginHandoff,
  newLoginState,
  openIdToUnionId,
  openLoginHandoff,
  openLoginState,
  parseFeishuCredential,
  parseMeegoCredential,
  queryMeegoUserKeyByUnionId,
  renderLoginFailedHtml,
  renderLoginSuccessHtml,
  rotateLoginKey,
} from '../feishuLogin'
import {
  finishMcpAuthorization,
  OAUTH_CALLBACK_PATH,
  openOAuthState,
  renderOAuthCallbackHtml,
} from '../oauth'
import { assertContextAlive, contextObjectStoreFor } from '../contextNodes'
import { finishProviderAuthorization } from '../providerOAuth'
import { runHandler, tbErrorResponse } from '../responses'
import { requirePluginExport } from '../toolNodes'
import { verifyRefToken } from '../refToken'

/**
 * provider 型 OAuth 的回调段(kind:'tool')。失败一律渲染失败页而非抛错:这是浏览器
 * 直达的端点,用户该看到一句人话,而不是 JSON 错误体。
 */
async function finishToolAuthorization(opts: {
  code: string
  deps: RouteEnv['deps']
  encryptionKey: string
  node: TreeNode
  origin: string
  verifier: string
}): Promise<Response> {
  const config = opts.node.config as { authRef?: string, export?: string, provider: string }
  try {
    const { export: exported } = await requirePluginExport(
      opts.deps,
      config.provider,
      'tool',
      'tool',
      config.export,
    )
    if (exported.oauth === undefined || config.authRef === undefined) {
      return renderOAuthCallbackHtml(false, 'target node is not an OAuth-backed tool mount')
    }
    await finishProviderAuthorization({
      authRef: config.authRef,
      code: opts.code,
      codeVerifier: opts.verifier,
      config: exported.oauth,
      encryptionKey: opts.encryptionKey,
      fetcher: fetch,
      nodePath: opts.node.path,
      now: new Date(),
      origin: opts.origin,
      secrets: opts.deps.secrets,
      store: opts.deps.state,
    })
  } catch (err) {
    return renderOAuthCallbackHtml(false, isTBError(err) ? err.message : 'token exchange failed')
  }
  return renderOAuthCallbackHtml(true, `挂载 '${opts.node.path}' 已完成授权`)
}

/** Dashboard 飞书登录交接 Cookie:仅交给同源消费端点,不进 URL/JS/普通 API 请求。 */
function loginHandoffCookie(value: string, requestUrl: string, maxAge = HANDOFF_TTL_SEC): string {
  return generateCookie(FEISHU_HANDOFF_COOKIE, value, {
    httpOnly: true,
    maxAge,
    path: FEISHU_HANDOFF_PATH,
    sameSite: 'Strict',
    secure: new URL(requestUrl).protocol === 'https:',
  })
}

/** 消费成功/失败均清 Cookie;浏览器正常流程只能交接一次。 */
function clearLoginHandoffCookie(requestUrl: string): string {
  return loginHandoffCookie('', requestUrl, 0)
}

/** 交接端点失败保持统一 TBError 形状,且不区分缺失、篡改、过期。 */
function loginHandoffError(requestUrl: string, status: 401 | 403): Response {
  return new Response(
    JSON.stringify({
      code: 'permission_denied',
      message: status === 403 ? '飞书登录交接只允许同源控制台消费' : '飞书登录交接已失效，请重新登录',
      retryable: false,
    } satisfies TBErrorBody),
    {
      status,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'private, no-store',
        'set-cookie': clearLoginHandoffCookie(requestUrl),
      },
    },
  )
}

/**
 * meego 自动绑定注入面装配(open_id → union_id → user_key)。缺 meegoBind → null(不绑,SK 照发)。
 *
 * 链路(2026-07-25 真机全链路验证):登录 open_id → 登录 app 通讯录转 union_id →
 * meego user/query{out_ids} 查 user_key → merge 写回 nodePath 的 providerConfig.userKeys。
 * meego out_id 即 union_id(on_ 前缀),out_ids 直查一步命中。操作人 X-USER-KEY 取节点
 * 现有 userKeys 任一已绑成员(仅作合法操作人头,不影响查询目标)。
 */
function meegoBindDepsFor(deps: TbAppDeps): MeegoBindDeps | null {
  const cfg = deps.meegoBind
  if (cfg === undefined) return null
  const registry = new NodeRegistryStore(deps.state)
  const nodePath = normalizePath(cfg.nodePath)
  const loginRef = cfg.loginSecretRef ?? deps.feishuLoginSecretRef

  const readUserKeys = async (): Promise<Record<string, string>> => {
    const node = await registry.get(nodePath).catch(() => null)
    const pc = (node?.config as { providerConfig?: { userKeys?: unknown } } | undefined)?.providerConfig
    const uk = pc?.userKeys
    return typeof uk === 'object' && uk !== null ? { ...(uk as Record<string, string>) } : {}
  }

  return {
    getMeegoUserKeys: readUserKeys,
    setMeegoUserKeys: async (next) => {
      const node = await registry.get(nodePath)
      const config = { ...(node.config as Record<string, unknown>) }
      const providerConfig = { ...((config.providerConfig as Record<string, unknown>) ?? {}), userKeys: next }
      await registry.update(
        nodePath,
        { config: { ...config, providerConfig } as unknown as NodeConfig },
        new Date().toISOString(),
      )
    },
    loginOpenIdToUnionId: async (openId) => {
      if (loginRef === undefined) return null
      const cred = parseFeishuCredential(await deps.secrets.resolve(loginRef), loginRef)
      const appToken = await feishuAppAccessToken(cred)
      return await openIdToUnionId(appToken, openId)
    },
    queryUserKeyByUnionId: async (unionId) => {
      const meegoCred = parseMeegoCredential(await deps.secrets.resolve(cfg.secretRef), cfg.secretRef)
      const operator = Object.values(await readUserKeys())[0]
      if (operator === undefined) return null
      return await queryMeegoUserKeyByUnionId(meegoCred, operator, unionId)
    },
  }
}

export function registerPublicRoutes(app: TbHono, env: RouteEnv): void {
  const { deps } = env

  // GET /healthz → 200 JSON,树外免认证。version 单一真源:宿主 package.json。
  //
  // `catalog` 回显**装配了几个内置集成**与目录级 digest(未装配则整个字段缺席)。
  // 用途是三宿主对拍:同一个 commit 部署到 Workers 与 Node/Docker,两边这个 digest 必须
  // 相同。digest 只覆盖 (id, per-entry digest) 对,故改一个 provider 的文案不会翻动它。
  //
  // 免认证暴露它是安全的:那是一串 sha256 与一个计数,不含 provider 名更不含凭证;
  // 而部署诊断恰恰需要在拿到 SK 之前就能看。
  app.get('/healthz', async (c) => {
    const catalog = deps.pluginCatalog
    const digest = await env.pluginCatalogDigest()
    return c.json({
      healthy: true,
      version: deps.version,
      ...(catalog !== undefined && digest !== undefined
        ? { catalog: { count: Object.keys(catalog).length, digest } }
        : {}),
    })
  })

  // GET /~ref/<token> → 大对象中转下载,树外免认证(中转下载路由)。
  // 注册在认证中间件之前:token 本身即凭证(HMAC 限时签名);验签失败/过期一律 404 不泄露。
  app.get('/~ref/:token', c =>
    runHandler(async () => {
      const encKey = deps.encryptionKey
      if (encKey === undefined) throw TBError.notFound('not found')
      const payload = await verifyRefToken(c.req.param('token'), encKey)
      if (payload === null || payload.exp * 1000 <= Date.now()) throw TBError.notFound('not found')
      await deps.ensureReady?.()
      const registry = new NodeRegistryStore(deps.state)
      let node: TreeNode
      try {
        node = await registry.get(payload.p)
      } catch {
        throw TBError.notFound('not found')
      }
      // 签发后节点可能被卸载/换 kind/ttl 到期——须仍是存活的 context/skillhub 对象节点。
      const cfg = node.config
      if (
        (node.kind !== 'context' && node.kind !== 'skillhub')
        || cfg === undefined
        || cfg.kind !== node.kind
      ) {
        throw TBError.notFound('not found')
      }
      await assertContextAlive(node, cfg, registry)
      const objects = await contextObjectStoreFor(cfg, deps)
      const got = await objects.get(payload.k)
      if (got === null) throw TBError.notFound('not found')
      // core 的最小流形状与全局 ReadableStream 结构兼容(Workers/Node 皆然)。
      return new Response(got.body as unknown as ReadableStream, {
        headers: {
          'content-type': got.meta.contentType ?? 'application/octet-stream',
          'cache-control': 'private, no-store',
        },
      })
    }),
  )

  // --- /ui Dashboard 静态资源(Workers Static Assets)---
  // 一切请求先进本 app,静态资源仅由 assets 注入点显式转发,SPA 回退只在 /ui 内生效——
  // 不可能吞根 ~help、POST 数据面与 system/*。
  // /ui 免认证:登录页本身须在无 SK 时可加载(SK 只存浏览器,静态资源不含机密)。
  const serveUi = async (c: AppContext): Promise<Response> => {
    const assets = deps.assets
    if (assets === undefined) {
      return tbErrorResponse(TBError.notFound('dashboard assets not deployed'))
    }
    const url = new URL(c.req.url)
    // 构建产物是站点根布局(index.html + assets/*),/ui 挂载前缀在此剥离。
    const sub = url.pathname.slice('/ui'.length) || '/'
    const res = await assets(new Request(new URL(sub, url.origin)))
    if (res.status !== 404) return res
    // SPA 回退(仅 /ui 内):深链交给前端路由,由 '/' 取回 index.html。
    return await assets(new Request(new URL('/', url.origin)))
  }
  app.get('/ui', c => c.redirect('/ui/', 302))
  app.get('/ui/*', serveUi)

  // 浏览器直开根路径 → Dashboard(GET / 且 Accept 带 text/html 时 302);
  // 非 HTML 客户端(Agent/CLI)落回后续路由,行为与此前一致(401/404)。
  app.get('/', async (c, next) => {
    if (c.req.header('accept')?.includes('text/html')) return c.redirect('/ui/', 302)
    await next()
  })

  // GET /~oauth/callback → mcp 托管 OAuth 的授权回调,树外免认证(浏览器跳转无法带 SK)。
  // state 本身即凭证:AES-GCM 加密载荷(nodePath + code_verifier + exp),解不开/过期一律拒。
  app.get(OAUTH_CALLBACK_PATH, c =>
    runHandler(async () => {
      const encKey = deps.encryptionKey
      if (encKey === undefined) throw TBError.notFound('not found')
      const q = c.req.query()
      // AS 用户拒绝授权等错误回跳(error=access_denied 等):展示失败页,不泄露内部状态。
      if (q.error !== undefined) {
        return renderOAuthCallbackHtml(false, `authorization server returned: ${q.error}`)
      }
      const code = q.code
      const state = q.state
      if (code === undefined || state === undefined) {
        return renderOAuthCallbackHtml(false, 'missing code or state parameter')
      }
      const payload = await openOAuthState(state, encKey)
      if (payload === null || payload.exp * 1000 <= Date.now()) {
        return renderOAuthCallbackHtml(false, 'state is invalid or expired; restart authorization')
      }
      await deps.ensureReady?.()
      const registry = new NodeRegistryStore(deps.state)
      let node: TreeNode
      try {
        node = await registry.get(payload.p)
      } catch {
        return renderOAuthCallbackHtml(false, 'target node no longer exists')
      }
      // 两套 OAuth 流程共用这一个回调端点,按目标节点的 kind 分派:state 里的 `p` 已经是
      // 节点路径,不需要在 state 里再塞一个流程标记(那会多一处可被篡改的输入)。
      if (node.kind === 'tool' && node.config?.kind === 'tool') {
        return await finishToolAuthorization({
          code,
          deps,
          encryptionKey: encKey,
          node,
          origin: deps.canonicalOrigin ?? new URL(c.req.url).origin,
          verifier: payload.v,
        })
      }
      if (node.kind !== 'mcp' || node.config?.kind !== 'mcp' || node.config.auth !== 'oauth') {
        return renderOAuthCallbackHtml(false, 'target node is not an OAuth-backed mount')
      }
      try {
        await finishMcpAuthorization({
          store: deps.state,
          encryptionKey: encKey,
          nodePath: payload.p,
          serverUrl: node.config.url,
          origin: deps.canonicalOrigin ?? new URL(c.req.url).origin,
          code,
          codeVerifier: payload.v,
          // 本地回调通道(CLI --local):兑换必须复用授权时的 redirect_uri。
          ...(payload.r !== undefined ? { redirectUri: payload.r } : {}),
        })
      } catch (err) {
        const detail = isTBError(err) ? err.message : 'token exchange failed'
        return renderOAuthCallbackHtml(false, detail)
      }
      return renderOAuthCallbackHtml(true, `mcp mount '${payload.p}' is now authorized`)
    }),
  )

  // ---------- 飞书登录换 key(树外免认证:浏览器直达,无 SK)----------

  // 飞书登录换 key:redirect_uri 钉在 canonicalOrigin(或请求 origin)。
  const loginRedirectUri = (c: AppContext): string =>
    `${deps.canonicalOrigin ?? new URL(c.req.url).origin}${FEISHU_CALLBACK_PATH}`

  // Dashboard 启动时探测飞书登录是否真正可用:实例已初始化 + 凭证存在且形状正确。
  // 只回布尔值,不向公开端点泄露具体缺项、引用名或凭证内容。
  app.get(FEISHU_LOGIN_STATUS_PATH, async () => {
    let enabled = false
    const secretRef = deps.feishuLoginSecretRef
    if (deps.encryptionKey !== undefined && secretRef !== undefined) {
      try {
        await deps.ensureReady?.()
        parseFeishuCredential(await deps.secrets.resolve(secretRef), secretRef)
        enabled = true
      } catch {
        // fail closed:配置未就绪时 Dashboard 自动降级到手工 SK。
      }
    }
    return new Response(JSON.stringify({ enabled }), {
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'private, no-store',
      },
    })
  })

  // Dashboard 用飞书 OAuth 换到 SK 后,在同源 POST 中消费短时 HttpOnly 交接 Cookie。
  // Origin 必须精确匹配当前请求 origin;成功/失败都清 Cookie,响应与缓存隔离。
  app.post(FEISHU_HANDOFF_PATH, c =>
    runHandler(async () => {
      const requestUrl = c.req.url
      const requestOrigin = new URL(requestUrl).origin
      if (c.req.header('origin') !== requestOrigin) return loginHandoffError(requestUrl, 403)

      const encKey = deps.encryptionKey
      const value = getCookie(c, FEISHU_HANDOFF_COOKIE)
      if (encKey === undefined || value === undefined) return loginHandoffError(requestUrl, 401)

      const payload = await openLoginHandoff(value, encKey)
      if (payload === null || payload.exp * 1000 <= Date.now()) {
        return loginHandoffError(requestUrl, 401)
      }
      return new Response(
        JSON.stringify({
          baseUrl: payload.b,
          sk: payload.s,
          profile: 'feishu',
          ...(payload.u !== undefined ? { userName: payload.u } : {}),
        }),
        {
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'private, no-store',
            'set-cookie': clearLoginHandoffCookie(requestUrl),
          },
        },
      )
    }),
  )

  // GET /login → 生成加密 state,302 跳飞书授权页。树外免认证(无 SK 时可访问)。
  app.get('/login', c =>
    runHandler(async () => {
      const encKey = deps.encryptionKey
      const secretRef = deps.feishuLoginSecretRef
      if (encKey === undefined || secretRef === undefined) {
        return renderLoginFailedHtml('飞书登录未启用(缺 encryptionKey 或 feishuLoginSecretRef)')
      }
      let cred: ReturnType<typeof parseFeishuCredential> | null = null
      try {
        await deps.ensureReady?.()
        cred = parseFeishuCredential(await deps.secrets.resolve(secretRef), secretRef)
      } catch {
        return renderLoginFailedHtml('飞书登录当前不可用，请联系管理员检查网关初始化与应用凭证')
      }
      const continueTo = c.req.query('continue')
      if (continueTo !== undefined && continueTo !== FEISHU_DASHBOARD_PATH) {
        return renderLoginFailedHtml('登录回跳目标不受支持')
      }
      const state = await newLoginState(encKey, Date.now(), {
        dashboard: continueTo === FEISHU_DASHBOARD_PATH,
      })
      const url = buildAuthorizeUrl(cred.app_id, loginRedirectUri(c), state)
      return c.redirect(url, 302)
    }),
  )

  // GET /~feishu/callback → 校验 state → 换 token → 拿 open_id → rotate 签发 → meego 绑定 → 展示 SK。
  app.get(FEISHU_CALLBACK_PATH, c =>
    runHandler(async () => {
      const encKey = deps.encryptionKey
      const secretRef = deps.feishuLoginSecretRef
      if (encKey === undefined || secretRef === undefined) {
        return renderLoginFailedHtml('飞书登录未启用')
      }
      const q = c.req.query()
      if (q.error !== undefined) return renderLoginFailedHtml(`飞书返回:${q.error}`)
      const code = q.code
      const state = q.state
      if (code === undefined || state === undefined) {
        return renderLoginFailedHtml('缺 code 或 state 参数')
      }
      const payload = await openLoginState(state, encKey)
      if (payload === null || payload.exp * 1000 <= Date.now()) {
        return renderLoginFailedHtml('state 非法或已过期,请重新登录')
      }
      await deps.ensureReady?.()
      const cred = parseFeishuCredential(await deps.secrets.resolve(secretRef), secretRef)
      let openId: string
      let name: string | undefined
      try {
        const userToken = await exchangeUserToken(cred, code, loginRedirectUri(c))
        const info = await fetchUserInfo(userToken)
        openId = info.open_id
        name = info.name
      } catch (err) {
        return renderLoginFailedHtml(isTBError(err) ? err.message : '飞书授权失败')
      }
      const now = new Date().toISOString()
      const sk = new SKRegistryStore(deps.state)
      const { keyId, secret } = await rotateLoginKey(sk, openId, now, {
        ttlSec: deps.feishuLoginKeyTtlSec ?? DEFAULT_KEY_TTL_SEC,
      })
      // meego 自动绑定(best-effort;projectKey 未配则跳过)。
      let meegoNote: string | undefined
      const bindDeps = meegoBindDepsFor(deps)
      if (bindDeps !== null) {
        const r = await bindMeegoIdentity(bindDeps, keyId, openId)
        meegoNote = r.bound
          ? `已绑定 meego 操作人身份(user_key=${r.userKey}),评论/写操作将以你本人落地。`
          : `meego 身份未自动绑定(${r.reason}),如需 meego 写操作请联系管理员绑定。`
      }
      const baseUrl = deps.canonicalOrigin ?? new URL(c.req.url).origin
      if (payload.d === true) {
        const handoff = await newLoginHandoff(
          { secret, baseUrl, ...(name !== undefined ? { name } : {}) },
          encKey,
          Date.now(),
        )
        const response = c.redirect(`${FEISHU_DASHBOARD_PATH}?login=feishu`, 302)
        response.headers.set('cache-control', 'private, no-store')
        response.headers.append('set-cookie', loginHandoffCookie(handoff, c.req.url))
        return response
      }
      return renderLoginSuccessHtml({
        secret,
        baseUrl,
        ...(name !== undefined ? { name } : {}),
        ...(meegoNote !== undefined ? { meegoNote } : {}),
      })
    }),
  )
}
