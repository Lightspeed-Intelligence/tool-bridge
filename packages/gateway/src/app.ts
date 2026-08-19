import {
  createTbApp,
  ensureBootstrapped,
  parseS3Credentials,
  type PluginBindings,
  type RemoteSettings,
  type TbAppDeps,
} from '@tool-bridge/app'
import {
  type BuiltinCatalog,
  normalizeCanonicalOrigin,
  SecretStoreImpl,
  type StateStore,
} from '@tool-bridge/core'
import { Hono } from 'hono'
import type { DeviceSession } from './deviceSession'
import { createR2ObjectStore, type R2PresignCredentials } from './providers/r2Object'
import pkg from '../package.json' with { type: 'json' }
import { D1SearchIndex } from './search/d1SearchIndex'
import { KvStateStore } from './kvStateStore'

/**
 * Workers 运行时绑定。KV/R2 名称从 TB_NAME_PREFIX 派生(wrangler.jsonc)。
 * TB_SECRET_ENCRYPTION_KEY / TB_BOOTSTRAP_ADMIN_SK 经 wrangler secret 或 .dev.vars 注入。
 */
export interface Env {
  /** Dashboard 静态资源(Workers Static Assets;本地测试/未部署 UI 时可缺省)。 */
  ASSETS?: Fetcher
  /** 放行 http:// 上游(仅本地开发)。 */
  TB_ALLOW_INSECURE_HTTP?: string
  TB_BOOTSTRAP_ADMIN_SK?: string
  /**
   * 规范网关 origin(如 https://tool-bridge.example.com)。多域名部署时钉死 OAuth
   * redirect_uri,防授权 code 跨域互换;缺省用请求期 origin(单域名行为不变)。
   */
  TB_CANONICAL_ORIGIN?: string
  /** DeviceSession Durable Object(设备 WS hibernation)。 */
  TB_DEVICE: DurableObjectNamespace<DeviceSession>
  /** 设备断线后未重连的回收秒数(缺省 24h)。 */
  TB_DEVICE_RECLAIM_SEC?: string
  /** 飞书登录:签发 key 有效期秒(缺省 90 天)。 */
  TB_FEISHU_LOGIN_KEY_TTL_SEC?: string
  /** 飞书登录:SecretStore 中 {app_id,app_secret} 的引用名(缺省复用 feishu plugin 的 "feishu-app")。设置后启用 /login。 */
  TB_FEISHU_LOGIN_SECRET_REF?: string
  /** 本实例 X-TB-Via 标识(缺省用入站 host 派生)。 */
  TB_INSTANCE_ID?: string
  TB_KV: KVNamespace
  /** X-TB-Via 跳数上限(默认 4)。 */
  TB_MAX_HOPS?: string
  /** meego 自动绑定:承载 userKeys 映射的 tool 节点路径(如 "plugins/meego")。与 SECRET_REF 都配才启用。 */
  TB_MEEGO_BIND_NODE?: string
  /** meego 自动绑定:转 union_id 用的登录 app 凭证引用(缺省复用 TB_FEISHU_LOGIN_SECRET_REF)。 */
  TB_MEEGO_LOGIN_SECRET_REF?: string
  /** meego 自动绑定:meego 插件凭证 {plugin_id,plugin_secret} 的 SecretStore 引用(如 "meego-app")。 */
  TB_MEEGO_SECRET_REF?: string
  TB_R2: R2Bucket
  /** r2 presign 凭证链的 env 段(SecretStore 'r2-presign' 优先)。 */
  TB_R2_ACCESS_KEY_ID?: string
  TB_R2_BUCKET?: string
  /** r2 presign 的 S3 兼容端点(https://<account>.r2.cloudflarestorage.com)与 bucket。 */
  TB_R2_S3_ENDPOINT?: string
  TB_R2_SECRET_ACCESS_KEY?: string
  /** context Get 的 $ref 内联阈值(字节,缺省 1 MiB)。 */
  TB_REF_THRESHOLD_BYTES?: string
  /** $ref URL(presign 与 /~ref 中转)有效期秒(缺省 900)。 */
  TB_REF_TTL_SEC?: string
  /** remote baseUrl 的 host 后缀白名单(逗号分隔;空 = 拒一切 remote)。 */
  TB_REMOTE_ALLOWLIST?: string
  /** FTS5/trigram 工具搜索索引；发布包宿主未配置 binding 时不暴露 search capability。 */
  TB_SEARCH?: D1Database
  TB_SECRET_ENCRYPTION_KEY?: string
  /** opt-in 集成测试:真实 MCP echo server 的 URL(仅测试注入)。 */
  TB_TEST_MCP_URL?: string
  TB_TEST_S3_ACCESS_KEY_ID?: string
  TB_TEST_S3_BUCKET?: string
  /** opt-in 集成测试:S3 兼容端点与凭证(仅测试注入)。 */
  TB_TEST_S3_ENDPOINT?: string
  TB_TEST_S3_SECRET_ACCESS_KEY?: string
  /** mcp 工具缓存 TTL 秒(默认 300)。 */
  TB_TOOL_CACHE_TTL?: string
}

/** http:// 上游是否放行(env `TB_ALLOW_INSECURE_HTTP=true`,仅本地开发)。 */
function allowInsecure(env: Env): boolean {
  return env.TB_ALLOW_INSECURE_HTTP === 'true'
}

const DEFAULT_MAX_HOPS = 4

/** env → remote 透传配置(TB_REMOTE_ALLOWLIST 逗号分隔;TB_MAX_HOPS 缺省 4)。 */
function remoteSettingsFromEnv(env: Env): RemoteSettings {
  const allowlist = (env.TB_REMOTE_ALLOWLIST ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0)
  const hops = Number(env.TB_MAX_HOPS)
  return {
    allowlist,
    maxHops: Number.isFinite(hops) && hops > 0 ? hops : DEFAULT_MAX_HOPS,
    ...(env.TB_INSTANCE_ID !== undefined && env.TB_INSTANCE_ID.length > 0
      ? { instanceId: env.TB_INSTANCE_ID }
      : {}),
    allowInsecure: allowInsecure(env),
  }
}

/** 正整数 env 解析(TB_TOOL_CACHE_TTL / TB_REF_THRESHOLD_BYTES / TB_REF_TTL_SEC);非法/缺省 → undefined。 */
function positiveIntEnv(value: string | undefined): number | undefined {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined
}

/**
 * r2 presign 凭证链(按序):SecretStore 保留名 'r2-presign' →
 * env TB_R2_ACCESS_KEY_ID/TB_R2_SECRET_ACCESS_KEY → 均缺则 undefined($ref 走 /~ref 中转)。
 * endpoint/bucket 亦缺则无从 presign。
 */
async function r2PresignCredentials(
  env: Env,
  secrets: SecretStoreImpl,
): Promise<R2PresignCredentials | undefined> {
  const endpoint = env.TB_R2_S3_ENDPOINT
  const bucket = env.TB_R2_BUCKET
  if (endpoint === undefined || bucket === undefined) return undefined
  const stored = await secrets.resolve('r2-presign')
  if (stored !== undefined) {
    return { endpoint, bucket, ...parseS3Credentials(stored, 'r2-presign') }
  }
  if (env.TB_R2_ACCESS_KEY_ID !== undefined && env.TB_R2_SECRET_ACCESS_KEY !== undefined) {
    return {
      endpoint,
      bucket,
      accessKeyId: env.TB_R2_ACCESS_KEY_ID,
      secretAccessKey: env.TB_R2_SECRET_ACCESS_KEY,
    }
  }
  return undefined
}

/** Env → TbAppDeps(Workers 宿主适配；D1 SearchIndex 是第五个宿主注入点)。 */
function depsFromEnv(env: Env): TbAppDeps {
  const state: StateStore = new KvStateStore(env.TB_KV)
  const secrets = new SecretStoreImpl(state, env.TB_SECRET_ENCRYPTION_KEY)
  const deps: TbAppDeps = {
    state,
    secrets,
    version: pkg.version,
    ensureReady: () => ensureBootstrapped(state, env),
    remote: remoteSettingsFromEnv(env),
    allowInsecureHttp: allowInsecure(env),
    objects: async () => createR2ObjectStore(env.TB_R2, await r2PresignCredentials(env, secrets)),
    device: {
      invoke: (deviceId, req) => env.TB_DEVICE.getByName(deviceId).invoke(req),
      ws: async (deviceId, request) => await env.TB_DEVICE.getByName(deviceId).fetch(request),
    },
  }
  if (env.TB_SEARCH !== undefined) deps.search = new D1SearchIndex(env.TB_SEARCH)
  if (env.TB_SECRET_ENCRYPTION_KEY !== undefined) deps.encryptionKey = env.TB_SECRET_ENCRYPTION_KEY
  const canonicalOrigin = normalizeCanonicalOrigin(env.TB_CANONICAL_ORIGIN)
  if (canonicalOrigin !== undefined) deps.canonicalOrigin = canonicalOrigin
  const assets = env.ASSETS
  if (assets !== undefined) deps.assets = request => assets.fetch(request)
  const ttl = positiveIntEnv(env.TB_TOOL_CACHE_TTL)
  if (ttl !== undefined) deps.toolCacheTtlSec = ttl
  const refThreshold = positiveIntEnv(env.TB_REF_THRESHOLD_BYTES)
  if (refThreshold !== undefined) deps.refThresholdBytes = refThreshold
  const refTtl = positiveIntEnv(env.TB_REF_TTL_SEC)
  if (refTtl !== undefined) deps.refTtlSec = refTtl
  // 飞书登录:配了 secret ref 才启用(缺省不开)。
  if (env.TB_FEISHU_LOGIN_SECRET_REF !== undefined && env.TB_FEISHU_LOGIN_SECRET_REF !== '') {
    deps.feishuLoginSecretRef = env.TB_FEISHU_LOGIN_SECRET_REF
  }
  const loginTtl = positiveIntEnv(env.TB_FEISHU_LOGIN_KEY_TTL_SEC)
  if (loginTtl !== undefined) deps.feishuLoginKeyTtlSec = loginTtl
  // meego 自动绑定:节点路径 + meego 凭证引用都配了才启用(open_id → union_id → user_key)。
  if (
    env.TB_MEEGO_BIND_NODE !== undefined && env.TB_MEEGO_BIND_NODE !== ''
    && env.TB_MEEGO_SECRET_REF !== undefined && env.TB_MEEGO_SECRET_REF !== ''
  ) {
    deps.meegoBind = {
      nodePath: env.TB_MEEGO_BIND_NODE,
      secretRef: env.TB_MEEGO_SECRET_REF,
      ...(env.TB_MEEGO_LOGIN_SECRET_REF !== undefined && env.TB_MEEGO_LOGIN_SECRET_REF !== ''
        ? { loginSecretRef: env.TB_MEEGO_LOGIN_SECRET_REF }
        : {}),
    }
  }
  return deps
}

/**
 * Workers 入口的 Hono app。Workers 的 env 只在请求期可得,故每 isolate 按 env 惰性
 * 装配一次 tb app(env 对象在同一 isolate 内稳定,WeakMap 命中;跨 isolate 各自装配)。
 *
 * `opts.pluginBindings`:进程内插件装配表(构建期打包进 Worker 的插件集合按名直调)。
 * 可以直接给一张表,也可以给一个 **`(env) => 表`** 的工厂 —— 后者是内置目录需要的形态:
 * `builtinPluginBindings(env)` 要读 env(它内部按白名单收窄后递给插件),而 env 在
 * `createApp()` 调用时还不存在。工厂与 app 一起按 env 缓存,每 isolate 只建一次。
 *
 * `opts.pluginCatalog`:那些插件的 descriptor(编译期常量,不读 env,故不需要工厂)。
 * 与 bindings **应当同源装配** —— 只给 bindings 的话插件调得动但解析不出 export。
 */
export function createApp(
  opts: {
    pluginBindings?: PluginBindings | ((env: Env) => PluginBindings)
    pluginCatalog?: BuiltinCatalog
  } = {},
): Hono<{ Bindings: Env }> {
  const apps = new WeakMap<Env, ReturnType<typeof createTbApp>>()
  const appFor = (env: Env): ReturnType<typeof createTbApp> => {
    let app = apps.get(env)
    if (app === undefined) {
      const bindings
        = typeof opts.pluginBindings === 'function' ? opts.pluginBindings(env) : opts.pluginBindings
      app = createTbApp({
        ...depsFromEnv(env),
        ...(bindings !== undefined ? { pluginBindings: bindings } : {}),
        ...(opts.pluginCatalog !== undefined ? { pluginCatalog: opts.pluginCatalog } : {}),
      })
      apps.set(env, app)
    }
    return app
  }
  const outer = new Hono<{ Bindings: Env }>()
  outer.all('*', c => appFor(c.env).fetch(c.req.raw))
  return outer
}
