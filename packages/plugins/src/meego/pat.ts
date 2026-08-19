/**
 * 飞书项目(Meego)plugin_token(PAT)换发与进程内缓存。
 *
 * - 凭证(plugin_id/plugin_secret)不由 plugin 自持:每次调用由平台经 X-TB-Upstream-Auth
 *   传入(挂载 config.authRef 平台代解析)——同一 plugin 部署可服务不同凭证的挂载,
 *   故缓存**按 plugin_id 键控**(模式同 feishu/tat.ts)。
 * - 换发:POST {domain}/open_api/authen/plugin_token,body {plugin_id,plugin_secret,type:0}
 *   (type 0=正式 plugin_token,1=虚拟 token 仅调试);响应 {error:{code,msg},data:{token,expire_time}},
 *   expire_time 单位秒(约 7200)。
 * - 缓存在 isolate 内存(无 KV):isolate 回收即重换发;换发是幂等轻请求,不值得引入持久层。
 * - 刷新余量 5min:调用时刻剩余不足余量即懒换发。
 * - `force` 绕过缓存直接换发——上游 401 的纠错路径不得回读缓存(教训同网关 mcp
 *   会话空列表防御:凡纠错路径都绕开缓存读)。
 */

import { TBError } from '@tool-bridge/core'
import { createGuardedFetch } from '../_runtime/guardedFetch'

/** 飞书项目 open_api 域名(私有化部署经 MEEGO_BASE_URL override)。 */
export const DEFAULT_BASE_URL = 'https://project.feishu.cn'

export const PLUGIN_TOKEN_PATH = '/open_api/authen/plugin_token'

const REFRESH_MARGIN_MS = 5 * 60_000

// plugin_secret 在 JSON body 中,307/308 跨源跳转会原样转发;换发端点不应跨源。
const meegoAuthFetch = createGuardedFetch({ crossOriginRedirect: 'error' })

interface CachedPat {
  expiresAtMs: number
  token: string
}

const cache = new Map<string, CachedPat>()

/** 测试用:清空进程内 PAT 缓存。 */
export function clearPatCache(): void {
  cache.clear()
}

export interface PatConfig {
  /** 换发端点 base override(测试/私有化部署);缺省飞书项目公网域名。 */
  baseUrl?: string
  pluginId: string
  pluginSecret: string
}

interface PatResponse {
  data?: { expire_time?: number, token?: string }
  error?: { code?: number, msg?: string }
}

/** 取可用 PAT:该 plugin_id 的缓存余量充足直接返回,否则换发并回填。 */
export async function pluginAccessToken(cfg: PatConfig, force = false): Promise<string> {
  const cached = cache.get(cfg.pluginId)
  if (!force && cached !== undefined && cached.expiresAtMs - Date.now() > REFRESH_MARGIN_MS) {
    return cached.token
  }
  let resp: Response
  try {
    resp = await meegoAuthFetch(`${cfg.baseUrl ?? DEFAULT_BASE_URL}${PLUGIN_TOKEN_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        plugin_id: cfg.pluginId,
        plugin_secret: cfg.pluginSecret,
        type: 0,
      }),
    })
  } catch (err) {
    throw new TBError(
      'unavailable',
      `Meego plugin_token 换发网络失败:${err instanceof Error ? err.message : String(err)}`,
      { retryable: true },
    )
  }
  const body = (await resp.json().catch(() => null)) as PatResponse | null
  const token = body?.data?.token
  if (!resp.ok || body === null || body.error?.code !== 0 || typeof token !== 'string') {
    throw new TBError(
      'unavailable',
      `Meego plugin_token 换发失败:HTTP ${resp.status} code=${body?.error?.code ?? '?'} ${body?.error?.msg ?? ''}`.trim(),
      { retryable: false },
    )
  }
  const expireSec = typeof body.data?.expire_time === 'number' ? body.data.expire_time : 0
  cache.set(cfg.pluginId, {
    token,
    expiresAtMs: Date.now() + expireSec * 1000,
  })
  return token
}
