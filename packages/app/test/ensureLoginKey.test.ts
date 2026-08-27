import { base64urlEncode, MemoryStateStore, SecretStoreImpl, SKRegistryStore } from '@tool-bridge/core'
import { describe, expect, it } from 'vitest'
import { defaultLoginScopes, ensureLoginKey, loginOwner } from '../src/feishuLogin'

const NOW = '2026-08-26T00:00:00.000Z'
const OPEN_ID = 'ou_alice'

function setup(): { secrets: SecretStoreImpl, sk: SKRegistryStore } {
  const store = new MemoryStateStore()
  const secrets = new SecretStoreImpl(
    store,
    base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),
  )
  return { sk: new SKRegistryStore(store), secrets }
}

describe('ensureLoginKey(登录 key:已有则复用,永久有效)', () => {
  it('首次登录:签发新 key,永久有效(无 expiresAt),scope 为登录默认', async () => {
    const { sk, secrets } = setup()
    const r = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)

    expect(r.reused).toBe(false)
    expect(r.secret).toMatch(/\S/)
    const raw = await sk.rawById(r.keyId)
    expect(raw?.owner).toBe(loginOwner(OPEN_ID))
    expect(raw?.expiresAt).toBeUndefined()
    expect(raw?.scopes).toEqual(defaultLoginScopes())
    // 明文已加密存下,供本人此后复制。
    expect(raw?.secretEnc).toBeDefined()
  })

  it('再次登录:复用同一把 key,明文相同,不产生第二把', async () => {
    const { sk, secrets } = setup()
    const first = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)
    const second = await ensureLoginKey(sk, secrets, OPEN_ID, '2026-09-01T00:00:00.000Z')

    expect(second.reused).toBe(true)
    expect(second.keyId).toBe(first.keyId)
    expect(second.secret).toBe(first.secret)

    // 该 owner 名下仍只有一把 key —— 这正是本次改动的目的。
    const page = await sk.list({ limit: 200 })
    const mine = page.items.filter(k => k.owner === loginOwner(OPEN_ID))
    expect(mine).toHaveLength(1)
  })

  it('不同用户互不影响:各自一把,互不复用', async () => {
    const { sk, secrets } = setup()
    const a = await ensureLoginKey(sk, secrets, 'ou_alice', NOW)
    const b = await ensureLoginKey(sk, secrets, 'ou_bob', NOW)

    expect(b.keyId).not.toBe(a.keyId)
    expect(b.secret).not.toBe(a.secret)
    expect((await sk.rawById(b.keyId))?.owner).toBe(loginOwner('ou_bob'))
  })

  it('历史 key 只有 hash(旧版签发)→ 不复用,签新的;旧的保留不删', async () => {
    const { sk, secrets } = setup()
    // 模拟旧版:无 secretEnc、带 TTL。
    const legacy = await sk.write(
      {
        owner: loginOwner(OPEN_ID),
        scopes: defaultLoginScopes(),
        description: 'feishu-login @ old',
        expiresAt: '2027-01-01T00:00:00.000Z',
      },
      NOW,
    )

    const r = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)
    expect(r.reused).toBe(false)
    expect(r.keyId).not.toBe(legacy.key.id)
    // 旧 key 不删:用户手上可能正在用,清理交给用户自助撤销。
    expect(await sk.rawById(legacy.key.id)).not.toBeNull()
  })

  it('已过期的 key 不复用(复用了也不能用)', async () => {
    const { sk, secrets } = setup()
    const first = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)
    await sk.update(first.keyId, { expiresAt: '2026-08-27T00:00:00.000Z' })

    const later = await ensureLoginKey(sk, secrets, OPEN_ID, '2026-09-01T00:00:00.000Z')
    expect(later.reused).toBe(false)
    expect(later.keyId).not.toBe(first.keyId)
  })

  it('已禁用的 key 不复用', async () => {
    const { sk, secrets } = setup()
    const first = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)
    await sk.update(first.keyId, { disabled: true })

    const again = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)
    expect(again.reused).toBe(false)
    expect(again.keyId).not.toBe(first.keyId)
  })

  it('自助签发的 key(非本流程标记)不会被登录流程复用或删除', async () => {
    const { sk, secrets } = setup()
    const self = await sk.write(
      { owner: loginOwner(OPEN_ID), scopes: defaultLoginScopes(), description: 'self-issued · cli' },
      NOW,
      async p => await secrets.encryptString(p),
    )

    const login = await ensureLoginKey(sk, secrets, OPEN_ID, NOW)
    // 没有复用自助 key(它不带 feishu-login 标记),也没被删。
    expect(login.keyId).not.toBe(self.key.id)
    expect(await sk.rawById(self.key.id)).not.toBeNull()
  })
})
