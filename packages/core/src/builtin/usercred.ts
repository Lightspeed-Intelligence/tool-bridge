/**
 * builtin 模块 "usercred" → 个人上游凭证(挂载为 system/my-credentials 节点)。
 *
 * 与 system/secret(admin 全局)不同:这是**本人自助面**。任何登录 SK 都能读写
 * **自己的**个人凭证,靠 `dispatch` 内 `ctx.owner` 硬圈定操作范围(入参只有 domain,
 * owner 一律取自 ctx,用户无法指定他人)——安全性来自「owner 来自 ctx 而非入参」,
 * 而非 scope 粒度。
 *
 * 存储:复用 SecretStoreImpl(AES-GCM),secret name = `usercred:<owner>:<domain>`。
 * 维度取 owner(即 user:<openId>)而非 keyId:open_id 跨登录稳定,rotate 换 keyId 后仍命中,
 * 免除迁移。value 只写不读:set 不回显、list 只出 domain + updatedAt。
 *
 * 网关注入面(mcp provider)经 {@link resolveUserCredential} 解析个人凭证,先于节点默认 authRef。
 */

import type { SecretStoreImpl } from '../secret/secretStore'
import type { CmdSpec, HelpModel } from '../htbp/model'
import type { OwnerRef, TreePath } from '../types'
import type { BuiltinModule } from './types'
import { cmdPath, VOID_ACK, withCommandPaths } from './util'
import { TBError } from '../errors'

/**
 * 取必填字符串字段。
 *
 * 上游把 builtin 的入参校验迁到了 BuiltinCommandRegistry 的 Zod `inputSchema`,
 * 随之删掉了 util 的 `requireString`。本模块(个人凭证,Lightspeed 定制)仍是
 * dispatch+switch 形态,校验语义不变,故就地保留一份等价实现 —— 比连带把本模块
 * 改写成 Registry 范式风险小,行为与旧 util 版逐字一致。
 */
function requireString(args: Record<string, unknown>, field: string): string {
  const v = args[field]
  if (typeof v !== 'string' || v.length === 0) {
    throw new TBError('invalid_argument', `field '${field}' must be a non-empty string`)
  }
  return v
}

const DESCRIPTION
  = 'Your personal upstream credentials: write-only, per-user; nodes with a credentialDomain '
    + 'use your token instead of the shared admin default. Values can never be read back.'

/** 一个可配个人凭证的域:哪个 domain、哪些节点用它、给用户看的说明。 */
export interface CredentialDomainInfo {
  /** 取首个用该域的节点描述作说明(可空)。 */
  description?: string
  domain: string
  /** 用该域的节点路径(供 UI 展示「这会影响哪些工具」)。 */
  nodePaths: string[]
}

/**
 * 发现可配域的注入面(网关扫节点注册表得到 credentialDomain 列表)。
 * core 不做 I/O:由网关注入。缺省则 `domains` cmd 只回用户已配的域(不含可发现的空域)。
 */
export type ListCredentialDomains = () => Promise<CredentialDomainInfo[]>

/** 保留命名空间前缀:个人凭证与平台凭证同住 secret: 命名空间,靠此段区分。 */
export const USERCRED_PREFIX = 'usercred:'

/** secret name = usercred:<owner>:<domain>。owner 本身含 ':'(如 user:ou_xxx),末段为 domain。 */
function userCredName(owner: OwnerRef, domain: string): string {
  return `${USERCRED_PREFIX}${owner}:${domain}`
}

/** domain 入参守卫:非空、不含 ':'(防越权拼到 usercred:<owner>:plugin-token:x 这类保留名)。 */
function assertDomain(domain: string): void {
  if (domain.includes(':')) {
    throw new TBError('invalid_argument', `credential domain must not contain ':' (got ${JSON.stringify(domain)})`)
  }
}

/**
 * 网关侧解析个人凭证(供 mcp/http provider):命中返回明文,否则 undefined(回落节点默认)。
 * 与 SecretStoreImpl.resolve 同为内部 API,不暴露为 cmd。
 */
export async function resolveUserCredential(
  secrets: SecretStoreImpl,
  owner: OwnerRef,
  domain: string,
): Promise<string | undefined> {
  return secrets.resolve(userCredName(owner, domain))
}

/** 列本人已配置的 domain:翻遍 secret 全量,过滤 usercred:<owner>: 前缀,剥到裸 domain。 */
async function listOwnDomains(
  secrets: SecretStoreImpl,
  owner: OwnerRef,
): Promise<Array<{ domain: string, updatedAt: string }>> {
  const wanted = `${USERCRED_PREFIX}${owner}:`
  const out: Array<{ domain: string, updatedAt: string }> = []
  let cursor: string | undefined
  do {
    const page = await secrets.list(cursor !== undefined ? { limit: 200, cursor } : { limit: 200 })
    for (const { name, updatedAt } of page.items) {
      if (name.startsWith(wanted)) out.push({ domain: name.slice(wanted.length), updatedAt })
    }
    cursor = page.cursor
  } while (cursor !== undefined)
  return out
}

function usercredCmds(nodePath: TreePath): CmdSpec[] {
  const path = cmdPath(nodePath)
  const domainProp = {
    domain: {
      type: 'string',
      description: 'credential domain declared on the node (e.g. "yunxiao"); ":" is reserved',
    },
  } as const
  return [
    {
      name: 'set',
      method: 'POST',
      path,
      h: 'store or rotate YOUR personal token for a credential domain; overrides the shared default',
      inputSchema: {
        type: 'object',
        properties: {
          ...domainProp,
          value: {
            type: 'string',
            description: 'the personal token; encrypted at rest, never echoed',
          },
        },
        required: ['domain', 'value'],
      },
      returns: 'void — value never echoed',
      scope: 'call',
    },
    {
      name: 'list',
      method: 'POST',
      path,
      h: 'list the credential domains YOU have configured (domains and timestamps only, never values)',
      inputSchema: { type: 'object', properties: {} },
      returns: 'Page<{ domain, updatedAt }>',
      scope: 'call',
    },
    {
      name: 'delete',
      method: 'POST',
      path,
      h: 'delete YOUR personal token for a domain; that domain falls back to the shared default',
      inputSchema: { type: 'object', properties: { ...domainProp }, required: ['domain'] },
      returns: 'void',
      scope: 'call',
    },
    {
      name: 'domains',
      method: 'POST',
      path,
      h: 'list credential domains you CAN configure (from mounted nodes) with your configured state',
      inputSchema: { type: 'object', properties: {} },
      returns: 'Page<{ domain, nodePaths, description?, configured, updatedAt? }>',
      scope: 'read',
    },
  ]
}

export function createUserCredModule(
  store: SecretStoreImpl,
  now: () => string,
  listDomains?: ListCredentialDomains,
): BuiltinModule {
  return {
    module: 'usercred',
    description: DESCRIPTION,
    help(nodePath: TreePath): HelpModel {
      return {
        node: { path: nodePath, kind: 'builtin', description: DESCRIPTION },
        // 上游契约:cmd.path 必须是完整直连路径 `/<nodePath>/<cmd.name>`,由
        // withCommandPaths 统一派生。少这一层会让 path 停在 `/<nodePath>`,被路由
        // 判成 "command path escapes node"(2026-08-26 合并上游时 7 个 MCP 集成测试据此失败)。
        cmds: withCommandPaths(nodePath, usercredCmds(nodePath)),
      }
    },
    async dispatch(cmd: string, args: Record<string, unknown>, ctx): Promise<unknown> {
      // owner 一律取自 ctx——用户无法读写他人凭证。
      const owner = ctx.owner
      switch (cmd) {
        case 'set': {
          const domain = requireString(args, 'domain')
          assertDomain(domain)
          await store.set(userCredName(owner, domain), requireString(args, 'value'), now())
          return VOID_ACK
        }
        case 'list':
          return { items: await listOwnDomains(store, owner) }
        case 'delete': {
          const domain = requireString(args, 'domain')
          assertDomain(domain)
          await store.delete(userCredName(owner, domain))
          return VOID_ACK
        }
        case 'domains': {
          // 可配域(节点声明的 credentialDomain)⋈ 本人已配状态。listDomains 缺省 → 仅回已配。
          const own = new Map(
            (await listOwnDomains(store, owner)).map(d => [d.domain, d.updatedAt] as const),
          )
          const available = listDomains !== undefined ? await listDomains() : []
          const seen = new Set<string>()
          const items = available.map((d) => {
            seen.add(d.domain)
            const updatedAt = own.get(d.domain)
            return {
              domain: d.domain,
              nodePaths: d.nodePaths,
              ...(d.description !== undefined ? { description: d.description } : {}),
              configured: updatedAt !== undefined,
              ...(updatedAt !== undefined ? { updatedAt } : {}),
            }
          })
          // 已配但当前无节点声明该域(节点被卸载/改域)的孤儿项也列出,便于清理。
          for (const [domain, updatedAt] of own) {
            if (!seen.has(domain)) items.push({ domain, nodePaths: [], configured: true, updatedAt })
          }
          return { items }
        }
        default:
          throw new TBError('invalid_argument', `unknown cmd '${cmd}' on system/usercred`)
      }
    },
  }
}
