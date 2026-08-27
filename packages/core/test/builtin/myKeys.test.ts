import { beforeEach, describe, expect, it } from 'vitest'
import type { BuiltinModule } from '../../src/builtin/types'
import type { CallContext, Scope } from '../../src/types'
import { base64urlEncode, SecretStoreImpl } from '../../src/secret/secretStore'
import { createMyKeysModule, SELF_KEY_TAG } from '../../src/builtin/myKeys'
import { SKRegistryStore } from '../../src/auth/sk'
import { MemoryStateStore } from '../../src/store'
import { isTBError } from '../../src/errors'

const NOW = '2026-08-26T00:00:00.000Z'
const alice: CallContext = { keyId: 'ka', owner: 'user:ou_alice', scopes: [], traceId: 't' }
const bob: CallContext = { keyId: 'kb', owner: 'user:ou_bob', scopes: [], traceId: 't' }

/** 服务端钉死的模板(模拟 defaultLoginScopes:无 admin、无 system/sk)。 */
const TEMPLATE: Scope[] = [
  { pattern: 'mcp/**', actions: ['read', 'call', 'write'] },
  { pattern: 'system/my-keys', actions: ['read', 'call'] },
]

// 纯 WebCrypto:core tsconfig 不含 DOM 类型,补最小声明。
declare const crypto: { getRandomValues(array: Uint8Array): Uint8Array }

function makeMasterKey(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
}

describe('builtin my-keys 模块(SK 自助面,per-owner)', () => {
  let store: MemoryStateStore
  let secrets: SecretStoreImpl
  let sk: SKRegistryStore
  let mod: BuiltinModule

  beforeEach(() => {
    store = new MemoryStateStore()
    secrets = new SecretStoreImpl(store, makeMasterKey())
    sk = new SKRegistryStore(store)
    mod = createMyKeysModule(sk, secrets, () => NOW, () => TEMPLATE)
  })

  it('help():全部 cmd 为 call/read,绝不出现 admin scope', () => {
    const help = mod.help('system/my-keys')
    expect(help.cmds.map(c => c.name).sort())
      .toEqual(['create', 'delete', 'list', 'reveal', 'update'])
    expect(help.cmds.some(c => c.scope === 'admin')).toBe(false)
    // 命令路径必须是完整直连路径(withCommandPaths),否则路由判 escapes node。
    expect(help.cmds.every(c => c.path === `/system/my-keys/${c.name}`)).toBe(true)
  })

  it('create:scope 恒为服务端模板 —— 请求体传 scopes/owner 一律无效(不提权)', async () => {
    const created = await mod.dispatch(
      'create',
      {
        description: 'laptop',
        // 恶意夹带:都不该生效。
        scopes: [{ pattern: '**', actions: ['admin'] }],
        owner: 'user:admin',
      },
      alice,
    ) as { id: string, scopes: Scope[], secret: string }

    expect(created.scopes).toEqual(TEMPLATE)
    expect(created.secret).toMatch(/\S/)
    // owner 只能是 ctx.owner。
    const raw = await sk.rawById(created.id)
    expect(raw?.owner).toBe(alice.owner)
    expect(raw?.scopes.some(s => s.actions.includes('admin'))).toBe(false)
  })

  it('create:默认永久(无 expiresAt);显式传则生效', async () => {
    const forever = await mod.dispatch('create', {}, alice) as { expiresAt?: string }
    expect(forever.expiresAt).toBeUndefined()

    const dated = await mod.dispatch(
      'create',
      { expiresAt: '2027-01-01T00:00:00.000Z' },
      alice,
    ) as { expiresAt?: string }
    expect(dated.expiresAt).toBe('2027-01-01T00:00:00.000Z')
  })

  it('create → reveal:本人可反复取回同一明文(可复制)', async () => {
    const created = await mod.dispatch('create', {}, alice) as { id: string, secret: string }
    const first = await mod.dispatch('reveal', { id: created.id }, alice) as { secret: string }
    const second = await mod.dispatch('reveal', { id: created.id }, alice) as { secret: string }
    expect(first.secret).toBe(created.secret)
    expect(second.secret).toBe(created.secret)
  })

  it('list:只列本人 key,且带 copyable 标记;看不到他人 key', async () => {
    await mod.dispatch('create', { description: 'a1' }, alice)
    await mod.dispatch('create', { description: 'b1' }, bob)

    const mine = await mod.dispatch('list', {}, alice) as {
      items: Array<{ copyable: boolean, description?: string, origin: string, owner: string }>
    }
    expect(mine.items).toHaveLength(1)
    expect(mine.items[0]?.owner).toBe(alice.owner)
    expect(mine.items[0]?.copyable).toBe(true)
    // 来源经 origin 表达;description 只留用户写的那段(前缀已剥)。
    expect(mine.items[0]?.origin).toBe('self')
    expect(mine.items[0]?.description).toBe('a1')
  })

  it('list/reveal:响应绝不含 hash 或 secretEnc', async () => {
    const created = await mod.dispatch('create', {}, alice) as { id: string }
    const page = await mod.dispatch('list', {}, alice) as { items: Array<Record<string, unknown>> }
    for (const item of page.items) {
      expect(item['hash']).toBeUndefined()
      expect(item['secretEnc']).toBeUndefined()
    }
    const revealed = await mod.dispatch('reveal', { id: created.id }, alice) as Record<string, unknown>
    expect(revealed['secretEnc']).toBeUndefined()
    expect(revealed['hash']).toBeUndefined()
  })

  it('越权防护:reveal / update / delete 他人 key 一律 not_found(不泄漏存在性)', async () => {
    const bobKey = await mod.dispatch('create', {}, bob) as { id: string }

    for (const cmd of ['reveal', 'update', 'delete']) {
      await expect(mod.dispatch(cmd, { id: bobKey.id }, alice)).rejects.toSatisfy(
        (e: unknown) => isTBError(e) && e.code === 'not_found',
      )
    }
    // bob 的 key 仍在(alice 的 delete 没生效)。
    expect(await sk.rawById(bobKey.id)).not.toBeNull()
  })

  it('update:能改描述与有效期,但改不了 scopes/owner', async () => {
    const created = await mod.dispatch('create', {}, alice) as { id: string }
    await mod.dispatch(
      'update',
      {
        id: created.id,
        description: 'renamed',
        // 恶意夹带:不该生效。
        scopes: [{ pattern: '**', actions: ['admin'] }],
        owner: 'user:admin',
      },
      alice,
    )
    const raw = await sk.rawById(created.id)
    expect(raw?.description).toContain('renamed')
    expect(raw?.scopes).toEqual(TEMPLATE)
    expect(raw?.owner).toBe(alice.owner)
  })

  it('update:expiresAt 传空串 = 清除过期(改永久)', async () => {
    const created = await mod.dispatch(
      'create',
      { expiresAt: '2027-01-01T00:00:00.000Z' },
      alice,
    ) as { id: string }
    await mod.dispatch('update', { id: created.id, expiresAt: '' }, alice)
    expect((await sk.rawById(created.id))?.expiresAt).toBeUndefined()
  })

  it('delete:撤销本人 key 后 list 不再出现', async () => {
    const created = await mod.dispatch('create', {}, alice) as { id: string }
    await mod.dispatch('delete', { id: created.id }, alice)
    const page = await mod.dispatch('list', {}, alice) as { items: unknown[] }
    expect(page.items).toHaveLength(0)
    expect(await sk.rawById(created.id)).toBeNull()
  })

  it('list:返回结构化 origin,description 只含用户自己写的那段(不泄漏来源前缀)', async () => {
    const tagged = createMyKeysModule(sk, secrets, () => NOW, () => TEMPLATE, {
      loginPrefix: 'feishu-login',
      delegationPrefix: 'oauth-access:',
    })
    // 自助签发(带用户描述)。
    await tagged.dispatch('create', { description: 'laptop CLI' }, alice)
    // 登录会话 key 与 OAuth 委托 key(模拟各自前缀)。
    await sk.write(
      { owner: alice.owner, scopes: TEMPLATE, description: 'feishu-login @ 2026-08-26' },
      NOW,
    )
    await sk.write(
      { owner: alice.owner, scopes: TEMPLATE, description: 'oauth-access:client-42' },
      NOW,
    )

    const page = await tagged.dispatch('list', {}, alice) as {
      items: Array<{ description?: string, origin: string }>
    }
    const byOrigin = new Map(page.items.map(i => [i.origin, i]))
    expect([...byOrigin.keys()].sort()).toEqual(['delegation', 'login', 'self'])
    // 用户写的描述保留、来源前缀被剥掉。
    expect(byOrigin.get('self')?.description).toBe('laptop CLI')
    // 登录 key 的 description 是内部时间戳,不该露给用户。
    expect(byOrigin.get('login')?.description).toBeUndefined()
    expect(byOrigin.get('delegation')?.description).toBe('client-42')
    // 任何 item 都不该残留原始前缀。
    for (const i of page.items) {
      expect(i.description ?? '').not.toContain('feishu-login')
      expect(i.description ?? '').not.toContain(SELF_KEY_TAG)
    }
  })

  it('delete 委托 key:触发连带清理(否则 refresh token 可换新 key 绕过撤销)', async () => {
    const calls: Array<{ description: string, owner: string }> = []
    const mod2 = createMyKeysModule(
      sk,
      secrets,
      () => NOW,
      () => TEMPLATE,
      { delegationPrefix: 'oauth-access:', loginPrefix: 'feishu-login' },
      async (owner, description) => {
        calls.push({ owner, description })
      },
    )
    const deleg = await sk.write(
      { owner: alice.owner, scopes: TEMPLATE, description: 'oauth-access:client-42' },
      NOW,
    )

    await mod2.dispatch('delete', { id: deleg.key.id }, alice)
    expect(calls).toEqual([{ owner: alice.owner, description: 'oauth-access:client-42' }])
  })

  it('delete 非委托 key:不触发连带清理', async () => {
    const calls: string[] = []
    const mod2 = createMyKeysModule(
      sk,
      secrets,
      () => NOW,
      () => TEMPLATE,
      { delegationPrefix: 'oauth-access:' },
      async (_owner, description) => {
        calls.push(description)
      },
    )
    const own = await mod2.dispatch('create', {}, alice) as { id: string }
    await mod2.dispatch('delete', { id: own.id }, alice)
    expect(calls).toEqual([])
  })

  it('reveal:历史 key(只有 hash、无 secretEnc)给出可操作的 invalid_argument', async () => {
    // 模拟旧版签发:不传 encryptSecret,记录里没有 secretEnc。
    const { key } = await sk.write({ owner: alice.owner, scopes: TEMPLATE }, NOW)
    await expect(mod.dispatch('reveal', { id: key.id }, alice)).rejects.toSatisfy(
      (e: unknown) => isTBError(e) && e.code === 'invalid_argument',
    )
  })
})
