/**
 * builtin 装配:把基础模块与宿主可选模块组装为 `module → BuiltinModule` 映射。
 *
 * 存储实例(SKRegistryStore / SecretStoreImpl / NodeRegistryStore)由网关注入并复用;
 * status 的 nodeCount 经翻页统计 registry 全量节点(当前树规模小,可接受)。
 */

import type { RemoteAllowlistStore } from '../tool/allowlist'
import type { SecretStoreImpl } from '../secret/secretStore'
import type { AnnotationStore } from '../annotation/store'
import type { NodeRegistryStore } from '../tree/registry'
import type { ScopeChecker } from '../tree/visibility'
import type { SKRegistryStore } from '../auth/sk'
import type { BuiltinModule } from './types'
import { createMyKeysModule, type OriginTags, type RevokeDelegationGrants } from './myKeys'
import { createUserCredModule, type CredentialDomainInfo } from './usercred'
import { type CatalogModuleDeps, createCatalogModule } from './catalog'
import { createPluginModule, type PluginModuleDeps } from './plugin'
import { createStoreModule, type StoreModuleDeps } from './store'
import { LIST_LIMIT_MAX, type Scope } from '../types'
import { createAnnotationModule } from './annotation'
import { createFederationModule } from './federation'
import { createRegistryModule } from './registry'
import { createSecretModule } from './secret'
import { createStatusModule } from './status'
import { createSkModule } from './sk'

export interface BuiltinDeps {
  /** annotation 模块装配(Path 补充说明;registry 复用上方注入)。缺省不装配。 */
  annotation?: { store: AnnotationStore }
  /**
   * catalog 模块装配:内置插件目录的只读浏览面(read scope)。
   * 缺省不装配 system/catalog —— 没装内置插件的宿主不该多一个恒空的节点。
   */
  catalog?: CatalogModuleDeps
  /**
   * federation 模块装配:remote host 白名单的运行时存储 + env 基线。
   * 缺省不装配 system/federation(纯逻辑单测无需)。
   */
  federation?: { base: string[], store: RemoteAllowlistStore }
  /** 时间源;缺省 `new Date().toISOString()`(测试可注入固定时钟)。 */
  now?: () => string
  /**
   * plugin 模块装配:store + 探活/契约抓取回调(I/O 在宿主)。
   * 缺省不装配 system/plugin(sk/secrets/now 复用上方注入)。
   */
  plugin?: Omit<PluginModuleDeps, 'sk' | 'secrets' | 'now'>
  registry: NodeRegistryStore
  /**
   * 自助撤销 OAuth 委托 key 时的连带清理(宿主注入;缺省则只删 SK)。
   * 不清 refresh token 的话撤销可被 refresh 绕过 —— 见 myKeys.RevokeDelegationGrants。
   */
  revokeDelegationGrants?: RevokeDelegationGrants
  secret: SecretStoreImpl
  /**
   * my-keys 的来源前缀(宿主注入):登录会话 key 与 OAuth 委托 key 的 description 前缀
   * 定义在 app 层,core 判定 origin 时需要它们。缺省则这两类都归为 'other'。
   */
  selfKeyOriginTags?: OriginTags
  /**
   * my-keys 模块装配:登录用户自助签发 SK 时**服务端钉死**的 scope 模板
   * (宿主传入登录默认那套)。缺省不装配 system/my-keys —— 没有登录体系的宿主
   * 不该多出一个能签发 key 的面。
   */
  selfKeyScopes?: () => Scope[]
  sk: SKRegistryStore
  /** 部署级 default Store；正式宿主应注入，纯 core 旧单测可缺省。 */
  store?: StoreModuleDeps
  /** 网关 version(单一真源:package.json),status.get 回显。 */
  version: () => string
  /**
   * 可见性判定(= auth/scope 的 checkScopes),注入给 registry 模块做可见性裁剪
   * (list 裁剪 / get→not_found)。网关装配一律传入;缺省则 registry 不裁剪(纯逻辑单测)。
   */
  visibility?: ScopeChecker
}

/** 翻页扫描节点注册表,聚合声明了 credentialDomain 的节点 → 可配个人凭证的域列表。 */
async function listCredentialDomains(
  registry: NodeRegistryStore,
): Promise<CredentialDomainInfo[]> {
  const byDomain = new Map<string, { description?: string, nodePaths: string[] }>()
  let cursor: string | undefined
  do {
    const page = await registry.list(undefined, {
      limit: LIST_LIMIT_MAX,
      ...(cursor !== undefined ? { cursor } : {}),
    })
    for (const node of page.items) {
      const cfg = node.config
      const domain
        = cfg !== undefined && cfg.kind === 'mcp' && typeof cfg.credentialDomain === 'string'
          ? cfg.credentialDomain
          : undefined
      if (domain === undefined || domain.length === 0) continue
      const entry = byDomain.get(domain) ?? { nodePaths: [] }
      entry.nodePaths.push(node.path)
      if (entry.description === undefined && node.description.length > 0) {
        entry.description = node.description
      }
      byDomain.set(domain, entry)
    }
    cursor = page.cursor
  } while (cursor !== undefined)
  return [...byDomain.entries()].map(([domain, v]) => ({
    domain,
    nodePaths: v.nodePaths,
    ...(v.description !== undefined ? { description: v.description } : {}),
  }))
}

/** 翻页统计 registry 全量节点数(status.nodeCount)。 */
async function countNodes(registry: NodeRegistryStore): Promise<number> {
  let count = 0
  let cursor: string | undefined
  do {
    const page: { cursor?: string, items: unknown[] } = await registry.list(undefined, {
      limit: LIST_LIMIT_MAX,
      ...(cursor !== undefined ? { cursor } : {}),
    })
    count += page.items.length
    cursor = page.cursor
  } while (cursor)
  return count
}

/** 构造 module 名 → BuiltinModule 映射；可选模块只在宿主提供依赖时装配。 */
export function createBuiltins(deps: BuiltinDeps): Map<string, BuiltinModule> {
  const now = deps.now ?? (() => new Date().toISOString())
  const modules = new Map<string, BuiltinModule>()
  modules.set('sk', createSkModule(deps.sk, now))
  modules.set('secret', createSecretModule(deps.secret, now))
  // 个人凭证自助面:复用 secret 存储(SecretStoreImpl),名字空间 usercred:<owner>:<domain>。
  // domains cmd 需发现「哪些节点声明了 credentialDomain」——从 registry 扫描聚合。
  modules.set('usercred', createUserCredModule(deps.secret, now, () => listCredentialDomains(deps.registry)))
  // SK 自助面:登录用户自己签发 / 复制 / 撤销自己的 key。scope 模板由宿主钉死,
  // 模块内不接受调用方传 scopes/owner(否则等于让任何登录用户提权)。
  if (deps.selfKeyScopes !== undefined) {
    modules.set(
      'my-keys',
      createMyKeysModule(
        deps.sk,
        deps.secret,
        now,
        deps.selfKeyScopes,
        deps.selfKeyOriginTags ?? {},
        deps.revokeDelegationGrants,
      ),
    )
  }
  modules.set('registry', createRegistryModule(deps.registry, now, deps.visibility))
  modules.set(
    'status',
    createStatusModule({ version: deps.version, nodeCount: () => countNodes(deps.registry) }),
  )
  if (deps.plugin !== undefined) {
    modules.set(
      'plugin',
      createPluginModule({ ...deps.plugin, sk: deps.sk, secrets: deps.secret, now }),
    )
  }
  if (deps.catalog !== undefined) {
    modules.set('catalog', createCatalogModule(deps.catalog))
  }
  if (deps.federation !== undefined) {
    modules.set(
      'federation',
      createFederationModule({ store: deps.federation.store, base: deps.federation.base, now }),
    )
  }
  if (deps.annotation !== undefined) {
    modules.set(
      'annotation',
      createAnnotationModule({ store: deps.annotation.store, registry: deps.registry, now }),
    )
  }
  if (deps.store !== undefined) {
    modules.set('store', createStoreModule(deps.store))
  }
  return modules
}

export {
  type AnnotationModuleDeps,
  createAnnotationModule,
} from './annotation'
export { type CatalogListItem, type CatalogModuleDeps, createCatalogModule } from './catalog'
export {
  createFederationModule,
  type FederationHost,
  type FederationModuleDeps,
} from './federation'
export {
  createPluginModule,
  type PluginHealthRecord,
  type PluginModuleDeps,
  type PluginProbeResult,
  type PluginRegistration,
  pluginTokenSecretName,
  type PluginView,
} from './plugin'
export { createRegistryModule, parseNodeInput } from './registry'
export { createSecretModule } from './secret'
export { createSkModule } from './sk'
export { createStatusModule, type StatusDeps, type StatusSummary } from './status'
export {
  createStoreModule,
  STORE_COMMANDS,
  type StoreCommand,
  type StoreModuleCallbacks,
  type StoreModuleDeps,
  storeScopeForCmd,
} from './store'
export type { BuiltinDispatchRuntime, BuiltinModule } from './types'
export {
  createUserCredModule,
  type CredentialDomainInfo,
  type ListCredentialDomains,
  resolveUserCredential,
  USERCRED_PREFIX,
} from './usercred'
