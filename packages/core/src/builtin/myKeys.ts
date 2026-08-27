/**
 * `system/my-keys` —— 登录用户的 SK 自助面。
 *
 * 为什么单独一个模块,而不是放宽 `system/sk` 的 admin 门槛:`system/sk/write` 接受
 * 调用方任意传 `owner` 与 `scopes`,且网关的 `checkScopes(scopes, path, action)` 只认
 * **节点路径**、不看参数(见 auth/scope.ts)。放宽门槛等于让任何登录用户签发 admin key
 * —— 直接提权。所以自助面自己承担两条参数级约束(同 assertRegisterPath / assertSecretRefUse
 * 的既有做法):
 *
 *   1. **owner 一律取自 `ctx.owner`**,请求体没有 owner 字段 —— 用户只能操作自己的 key。
 *   2. **scopes 由服务端钉死**(注入的 `defaultScopes()`),请求体没有 scopes 字段 ——
 *      用户签发的 key 权限恒等于登录默认那套,不能自选更大。
 *
 * 明文可复制(`reveal`):SK 记录里的 `secretEnc` 是主密钥加密的明文(见 SecretKey.secretEnc)。
 * 只有本人、且只对自己带该字段的 key 能解密取回;`projectKey` 已把 secretEnc 从所有常规
 * 读取路径剥掉,admin 面也拿不到他人明文。
 *
 * ⚠️ 这是一次明确的安全取舍(2026-08-26 定):存明文让 `TB_SECRET_ENCRYPTION_KEY` 成为
 * 单点(泄漏即所有带 secretEnc 的 SK 泄漏)。鉴权路径仍只比对 hash,永不读 secretEnc。
 */

import type { Scope, SecretKey, Timestamp, TreePath } from '../types'
import type { SecretStoreImpl } from '../secret/secretStore'
import type { CmdSpec, HelpModel } from '../htbp/model'
import type { SKRegistryStore } from '../auth/sk'
import type { BuiltinModule } from './types'
import { cmdPath, VOID_ACK, withCommandPaths } from './util'
import { TBError } from '../errors'

const DESCRIPTION
  = 'Your own secret keys: issue, copy and revoke keys for yourself. Keys carry the standard '
    + 'login permissions — you cannot grant yourself more. Never shows other people\'s keys.'

/** 自助签发的 key 打此标记,便于与飞书登录会话 key 区分、也不被登录 rotate 删掉。 */
export const SELF_KEY_TAG = 'self-issued'

/** 取必填字符串字段(本模块是 dispatch 形态,校验就地做;同 usercred)。 */
function requireString(args: Record<string, unknown>, field: string): string {
  const v = args[field]
  if (typeof v !== 'string' || v.length === 0) {
    throw new TBError('invalid_argument', `field '${field}' must be a non-empty string`)
  }
  return v
}

/** 取可选字符串字段;出现但非字符串 → invalid_argument。 */
function optString(args: Record<string, unknown>, field: string): string | undefined {
  const v = args[field]
  if (v === undefined) return undefined
  if (typeof v !== 'string' || v.length === 0) {
    throw new TBError('invalid_argument', `field '${field}' must be a non-empty string when present`)
  }
  return v
}

/**
 * 取回本人某把 key 的**原始记录**(含 secretEnc)。
 *
 * 不能用 `sk.get(id)` —— 它经 projectKey 投影,secretEnc 已被剥掉。这里直接扫本人 key
 * 列表定位记录本体。owner 不匹配一律按 not_found 处理(不是 permission_denied):
 * 避免让人探测"某个 id 存不存在、属于谁"。
 */
async function findOwnRawKey(
  sk: SKRegistryStore,
  owner: string,
  id: string,
): Promise<SecretKey | null> {
  const rec = await sk.rawById(id)
  if (rec === null || rec.owner !== owner) return null
  return rec
}

/** key 的来源(结构化;前端据此显示徽标,不必解析 description 前缀)。 */
export type MyKeyOrigin = 'delegation' | 'login' | 'other' | 'self'

/**
 * 来源前缀 → origin 的判定表。
 *
 * description 里编码了来源(`self-issued · x` / `feishu-login @ t` / `oauth-access:<id>`),
 * 但那是**存储层的实现细节**:让前端去 split 字符串会把三个散落在 core/app 的常量
 * 变成隐式契约,改名即静默失效。所以在这里判定完,只把 origin 与用户自己写的那段
 * description 送出去。login / delegation 的前缀在 app 层,故由宿主注入。
 */
export interface OriginTags {
  /** OAuth 委托签发的 access key 前缀(app 层 oauthDelegation)。 */
  delegationPrefix?: string
  /** 飞书登录会话 key 前缀(app 层 feishuLogin)。 */
  loginPrefix?: string
}

/**
 * 撤销 OAuth 委托 key 时的连带清理(宿主注入)。
 *
 * 委托授权由两份状态构成:access key(SK 记录)与 refresh token(`oauth:refresh:*`,
 * 独立条目)。只删 SK 的话第三方应用能用 refresh token 换一把新 access key —— **撤销被绕过**。
 * 官方撤销端点两者都清,自助撤销必须等价。清理逻辑在 app 层(OAuth 是那层的事),故注入。
 *
 * @param owner 被撤销 key 的 owner(= refresh 记录的 subject)。
 * @param description 该 key 的原始 description(含 `oauth-access:<clientId>` 前缀,用于取 clientId)。
 */
export type RevokeDelegationGrants = (owner: string, description: string) => Promise<void>

/** 拆出 origin 与用户可见描述(剥掉来源前缀与分隔符)。 */
function readOrigin(
  description: string | undefined,
  tags: OriginTags,
): { origin: MyKeyOrigin, text?: string } {
  const d = description ?? ''
  if (d.startsWith(SELF_KEY_TAG)) {
    const rest = d.slice(SELF_KEY_TAG.length).replace(/^\s*·\s*/, '').trim()
    return rest === '' ? { origin: 'self' } : { origin: 'self', text: rest }
  }
  if (tags.loginPrefix !== undefined && d.startsWith(tags.loginPrefix)) {
    return { origin: 'login' }
  }
  if (tags.delegationPrefix !== undefined && d.startsWith(tags.delegationPrefix)) {
    const rest = d.slice(tags.delegationPrefix.length).trim()
    return rest === '' ? { origin: 'delegation' } : { origin: 'delegation', text: rest }
  }
  return d === '' ? { origin: 'other' } : { origin: 'other', text: d }
}

/** 列出本人全部 key(投影后,不含 hash / secretEnc);附 copyable 与 origin。 */
async function listOwnKeys(
  sk: SKRegistryStore,
  owner: string,
  tags: OriginTags,
): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = []
  let cursor: string | undefined
  do {
    const page = await sk.list(cursor !== undefined ? { limit: 200, cursor } : { limit: 200 })
    for (const k of page.items) {
      if (k.owner !== owner) continue
      const raw = await sk.rawById(k.id)
      const { origin, text } = readOrigin(k.description, tags)
      out.push({
        ...k,
        // description 换成用户自己写的那段(不含来源前缀);没写过则不出现该字段。
        ...(text !== undefined ? { description: text } : { description: undefined }),
        origin,
        // 能否在页面上「复制」:仅当记录里存了可解密明文。历史签发的 key 只有 hash,
        // 永远取不回明文 —— 前端据此隐藏复制按钮,而不是让用户点了报错。
        copyable: raw?.secretEnc !== undefined,
      })
    }
    cursor = page.cursor
  } while (cursor !== undefined)
  return out
}

function myKeysCmds(nodePath: TreePath): CmdSpec[] {
  const path = cmdPath(nodePath)
  const idProp = {
    id: { type: 'string', description: 'key id (from list); must be one of YOUR keys' },
  } as const
  return [
    {
      name: 'create',
      method: 'POST',
      path,
      h: 'issue a new key for YOURSELF with the standard login permissions (never more)',
      inputSchema: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: 'what this key is for (e.g. "laptop CLI"); shown in your key list',
          },
          expiresAt: {
            type: 'string',
            description: 'optional ISO-8601 expiry; omit for a key that never expires',
          },
        },
      },
      // 明文在此响应里给一次,同时也存了密文 —— 之后可用 reveal 反复取回。
      returns: '{ id, secret, scopes, createdAt, expiresAt? } — secret also retrievable via reveal',
      scope: 'call',
    },
    {
      name: 'list',
      method: 'POST',
      path,
      h: 'list YOUR keys (id, description, scopes, lifecycle; never the secret itself)',
      inputSchema: { type: 'object', properties: {} },
      returns: '{ items: Array<{ id, description?, origin: "self"|"login"|"delegation"|"other", '
        + 'scopes, createdAt, expiresAt?, disabled?, copyable }> } — description is your own text '
        + 'only; origin says where the key came from',
      scope: 'call',
    },
    {
      name: 'reveal',
      method: 'POST',
      path,
      h: 'retrieve the plaintext of ONE of your own keys, so you can copy it again',
      inputSchema: { type: 'object', properties: { ...idProp }, required: ['id'] },
      returns: '{ id, secret }',
      scope: 'call',
    },
    {
      name: 'update',
      method: 'POST',
      path,
      h: 'edit YOUR key\'s description or expiry (permissions are fixed and cannot be changed)',
      inputSchema: {
        type: 'object',
        properties: {
          ...idProp,
          description: { type: 'string', description: 'new description' },
          expiresAt: {
            type: 'string',
            description: 'new ISO-8601 expiry; pass "" to clear it (never expires)',
          },
        },
        required: ['id'],
      },
      returns: 'the updated key (without the secret)',
      scope: 'call',
    },
    {
      name: 'delete',
      method: 'POST',
      path,
      h: 'revoke ONE of your own keys permanently; takes effect immediately',
      inputSchema: { type: 'object', properties: { ...idProp }, required: ['id'] },
      returns: 'void',
      scope: 'call',
    },
  ]
}

/**
 * @param sk SK 注册表(签发 / 列举 / 撤销)。
 * @param secrets 主密钥持有者,只用它的 encryptString / decryptString。
 * @param now 时钟。
 * @param defaultScopes 服务端钉死的 scope 模板(宿主注入,通常是登录默认那套)。
 */
export function createMyKeysModule(
  sk: SKRegistryStore,
  secrets: SecretStoreImpl,
  now: () => Timestamp,
  defaultScopes: () => Scope[],
  originTags: OriginTags = {},
  revokeDelegationGrants?: RevokeDelegationGrants,
): BuiltinModule {
  return {
    module: 'my-keys',
    description: DESCRIPTION,
    help(nodePath: TreePath): HelpModel {
      return {
        node: { path: nodePath, kind: 'builtin', description: DESCRIPTION },
        cmds: withCommandPaths(nodePath, myKeysCmds(nodePath)),
      }
    },
    async dispatch(cmd: string, args: Record<string, unknown>, ctx): Promise<unknown> {
      // owner 一律取自 ctx —— 请求体没有 owner 字段,用户无法操作他人 key。
      const owner = ctx.owner
      switch (cmd) {
        case 'create': {
          const description = optString(args, 'description')
          const expiresAt = optString(args, 'expiresAt')
          const { key, secret } = await sk.write(
            {
              owner,
              // scopes 恒为服务端模板:请求体无 scopes 字段,用户不能自选更大权限。
              scopes: defaultScopes(),
              description: `${SELF_KEY_TAG}${description !== undefined ? ` · ${description}` : ''}`,
              ...(expiresAt !== undefined ? { expiresAt } : {}),
            },
            now(),
            // 存可解密明文:本人此后可反复 reveal 复制。
            async plaintext => await secrets.encryptString(plaintext),
          )
          return { ...key, secret }
        }
        case 'list':
          return { items: await listOwnKeys(sk, owner, originTags) }
        case 'reveal': {
          const id = requireString(args, 'id')
          const rec = await findOwnRawKey(sk, owner, id)
          // 非本人 key 与不存在一视同仁:不泄漏他人 key 的存在。
          if (rec === null) throw TBError.notFound(`key '${id}' not found`)
          if (rec.secretEnc === undefined) {
            throw new TBError(
              'invalid_argument',
              `key '${id}' was issued before copyable keys existed; revoke it and create a new one`,
            )
          }
          return { id, secret: await secrets.decryptString(rec.secretEnc) }
        }
        case 'update': {
          const id = requireString(args, 'id')
          const rec = await findOwnRawKey(sk, owner, id)
          if (rec === null) throw TBError.notFound(`key '${id}' not found`)
          const description = optString(args, 'description')
          // expiresAt 显式传空串 = 清除过期(永久);未传 = 不动。
          const rawExpires = args['expiresAt']
          const patch: Record<string, unknown> = {}
          if (description !== undefined) {
            patch['description'] = `${SELF_KEY_TAG} · ${description}`
          }
          if (typeof rawExpires === 'string') {
            // 空串 = 改成永久;null 是 store 的显式清除信号(undefined 会被当成"不改动")。
            patch['expiresAt'] = rawExpires === '' ? null : rawExpires
          }
          // scopes / owner 不在可 patch 之列 —— 权限固定,改不了。
          return await sk.update(id, patch)
        }
        case 'delete': {
          const id = requireString(args, 'id')
          const rec = await findOwnRawKey(sk, owner, id)
          // 删他人 key 会成为拒绝服务手段,故同样按 not_found 拒绝。
          if (rec === null) throw TBError.notFound(`key '${id}' not found`)
          await sk.delete(id)
          // 委托 key:连带清掉 refresh token,否则第三方能用它换新 access key 绕过撤销。
          if (
            revokeDelegationGrants !== undefined
            && originTags.delegationPrefix !== undefined
            && (rec.description ?? '').startsWith(originTags.delegationPrefix)
          ) {
            await revokeDelegationGrants(owner, rec.description ?? '')
          }
          return VOID_ACK
        }
        default:
          throw TBError.notFound(`unknown command '${cmd}'`)
      }
    },
  }
}
