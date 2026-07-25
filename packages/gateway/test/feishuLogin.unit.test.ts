import { MemoryStateStore, SKRegistryStore } from '@tool-bridge/core'
import { describe, expect, it } from 'vitest'
import {
  bindMeegoIdentity,
  defaultLoginScopes,
  LOGIN_KEY_TAG,
  type MeegoBindDeps,
  newLoginState,
  openLoginState,
  rotateLoginKey,
  sealLoginState,
} from '../src/feishuLogin'

const SECRET = '3ZwpbBkSrp3eT9ylcZedfN33yq9fJLlmeusH98qNbt8'

describe('login state 封解', () => {
  it('roundtrip:封后能解回同一 payload', async () => {
    const state = await sealLoginState({ n: 'nonce123', exp: 9999999999 }, SECRET)
    const back = await openLoginState(state, SECRET)
    expect(back).toEqual({ n: 'nonce123', exp: 9999999999 })
  })

  it('换密钥解不开 → null', async () => {
    const state = await sealLoginState({ n: 'x', exp: 9999999999 }, SECRET)
    expect(await openLoginState(state, 'wrong-key-wrong-key-wrong-key-000')).toBeNull()
  })

  it('篡改密文 → null', async () => {
    const state = await sealLoginState({ n: 'x', exp: 9999999999 }, SECRET)
    const tampered = `${state.slice(0, -2)}xy`
    expect(await openLoginState(tampered, SECRET)).toBeNull()
  })

  it('格式非法 → null', async () => {
    expect(await openLoginState('nodot', SECRET)).toBeNull()
    expect(await openLoginState('', SECRET)).toBeNull()
  })

  it('newLoginState 带 exp = now + TTL', async () => {
    const now = 1_000_000_000_000
    const state = await newLoginState(SECRET, now)
    const p = await openLoginState(state, SECRET)
    expect(p).not.toBeNull()
    expect(p!.exp).toBe(Math.floor(now / 1000) + 600)
    expect(typeof p!.n).toBe('string')
    expect(p!.n.length).toBeGreaterThan(0)
  })
})

describe('defaultLoginScopes', () => {
  it('覆盖 mcp/plugins/skills 的 read+call+write,不含 system/admin', () => {
    const scopes = defaultLoginScopes()
    expect(scopes.map(s => s.pattern).sort()).toEqual(['mcp/**', 'plugins/**', 'skills/**'])
    for (const s of scopes) {
      expect(s.actions).toEqual(['read', 'call', 'write'])
    }
    const flat = JSON.stringify(scopes)
    expect(flat).not.toContain('admin')
    expect(flat).not.toContain('system')
  })
})

describe('rotateLoginKey', () => {
  const NOW = '2026-07-25T00:00:00.000Z'

  it('首次签发:owner=user:<openId>,带 login 标记,有过期', async () => {
    const sk = new SKRegistryStore(new MemoryStateStore())
    const { keyId, secret } = await rotateLoginKey(sk, 'ou_abc', NOW)
    expect(secret).toMatch(/^tbk_/)
    const key = await sk.get(keyId)
    expect(key.owner).toBe('user:ou_abc')
    expect(key.description?.startsWith(LOGIN_KEY_TAG)).toBe(true)
    expect(key.expiresAt).toBeDefined()
    expect(key.scopes.map(s => s.pattern).sort()).toEqual(['mcp/**', 'plugins/**', 'skills/**'])
  })

  it('rotate:同 owner 的旧登录 key 被删,只剩新的', async () => {
    const sk = new SKRegistryStore(new MemoryStateStore())
    const first = await rotateLoginKey(sk, 'ou_abc', NOW)
    const second = await rotateLoginKey(sk, 'ou_abc', NOW)
    expect(second.keyId).not.toBe(first.keyId)
    await expect(sk.get(first.keyId)).rejects.toThrow() // 旧的已删
    const alive = await sk.get(second.keyId)
    expect(alive.owner).toBe('user:ou_abc')
  })

  it('rotate 只删本 owner + 本流程签发的,不误删他人或非登录 key', async () => {
    const store = new MemoryStateStore()
    const sk = new SKRegistryStore(store)
    // 他人登录 key
    const other = await rotateLoginKey(sk, 'ou_other', NOW)
    // 一个非登录 key(admin 手签,description 不带标记)
    const manual = await sk.write(
      { owner: 'user:ou_abc', description: '手动签的', scopes: defaultLoginScopes() },
      NOW,
    )
    // 本人 rotate
    const mine = await rotateLoginKey(sk, 'ou_abc', NOW)
    expect((await sk.get(other.keyId)).owner).toBe('user:ou_other') // 他人未动
    expect((await sk.get(manual.key.id)).description).toBe('手动签的') // 非登录 key 未动
    expect((await sk.get(mine.keyId)).owner).toBe('user:ou_abc')
  })

  it('自定义 ttlSec 生效', async () => {
    const sk = new SKRegistryStore(new MemoryStateStore())
    const { keyId } = await rotateLoginKey(sk, 'ou_abc', NOW, { ttlSec: 3600 })
    const key = await sk.get(keyId)
    expect(key.expiresAt).toBe('2026-07-25T01:00:00.000Z')
  })
})

describe('bindMeegoIdentity(best-effort)', () => {
  const base = (over: Partial<MeegoBindDeps>): MeegoBindDeps => ({
    listMemberUserKeys: async () => ['uk1', 'uk2', 'uk3'],
    queryOutId: async keys =>
      Object.fromEntries(keys.map(k => [k, `out_${k}`])),
    getMeegoUserKeys: async () => ({ existing: 'ukX' }),
    setMeegoUserKeys: async () => {},
    ...over,
  })

  it('open_id 命中成员 out_id → 绑定并合并写回', async () => {
    let written: Record<string, string> | undefined
    const deps = base({
      queryOutId: async keys => Object.fromEntries(keys.map(k => [k, k === 'uk2' ? 'ou_target' : `out_${k}`])),
      setMeegoUserKeys: async (next) => {
        written = next
      },
    })
    const r = await bindMeegoIdentity(deps, 'newKeyId', 'ou_target')
    expect(r).toEqual({ bound: true, userKey: 'uk2' })
    expect(written).toEqual({ existing: 'ukX', newKeyId: 'uk2' }) // 合并,不覆盖已有
  })

  it('无成员候选 → 不绑定', async () => {
    const r = await bindMeegoIdentity(base({ listMemberUserKeys: async () => [] }), 'k', 'ou_x')
    expect(r.bound).toBe(false)
  })

  it('open_id 不匹配任何成员 → 不绑定(跨 app 不对齐场景)', async () => {
    const r = await bindMeegoIdentity(base({}), 'k', 'ou_nobody')
    expect(r.bound).toBe(false)
  })

  it('任何环节抛错 → 吞掉返回 bound:false,不阻断', async () => {
    const deps = base({
      listMemberUserKeys: async () => {
        throw new Error('meego down')
      },
    })
    const r = await bindMeegoIdentity(deps, 'k', 'ou_x')
    expect(r).toEqual({ bound: false, reason: 'meego down' })
  })
})
