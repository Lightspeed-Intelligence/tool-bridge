import { MemoryStateStore, SKRegistryStore } from '@tool-bridge/core'
import { describe, expect, it } from 'vitest'
import {
  bindMeegoIdentity,
  defaultLoginScopes,
  HANDOFF_TTL_SEC,
  LOGIN_KEY_TAG,
  type MeegoBindDeps,
  newLoginHandoff,
  newLoginState,
  openLoginHandoff,
  openLoginState,
  parseFeishuCredential,
  rotateLoginKey,
  sealLoginHandoff,
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

  it('Dashboard 发起时只在 state 内携带受控布尔标记', async () => {
    const state = await newLoginState(SECRET, 1_000_000_000_000, { dashboard: true })
    const payload = await openLoginState(state, SECRET)
    expect(payload?.d).toBe(true)
  })
})

describe('飞书应用凭证', () => {
  it('只接受真实飞书 app_id 格式，拒绝本地视觉占位值', () => {
    expect(parseFeishuCredential(
      '{"app_id":"cli_0123456789abcdef","app_secret":"secret_test"}',
      'feishu-app',
    )).toEqual({ app_id: 'cli_0123456789abcdef', app_secret: 'secret_test' })

    expect(() => parseFeishuCredential(
      '{"app_id":"cli_local_visual_check","app_secret":"secret_test"}',
      'feishu-app',
    )).toThrow('不是有效的飞书应用凭证')
  })
})

describe('Dashboard 登录交接封解', () => {
  it('roundtrip:SK/BaseURL/展示名完整还原,有效期为 120 秒', async () => {
    const now = 1_000_000_000_000
    const value = await newLoginHandoff(
      { baseUrl: 'https://tb.example.com', secret: 'tbk_handoff_secret', name: '测试用户' },
      SECRET,
      now,
    )
    expect(value).not.toContain('tbk_handoff_secret')
    expect(await openLoginHandoff(value, SECRET)).toEqual({
      b: 'https://tb.example.com',
      s: 'tbk_handoff_secret',
      u: '测试用户',
      exp: Math.floor(now / 1000) + HANDOFF_TTL_SEC,
    })
  })

  it('篡改、错密钥和非法 SK 形状一律拒绝', async () => {
    const value = await newLoginHandoff(
      { baseUrl: 'https://tb.example.com', secret: 'tbk_handoff_secret' },
      SECRET,
      Date.now(),
    )
    expect(await openLoginHandoff(`${value.slice(0, -2)}xx`, SECRET)).toBeNull()
    expect(await openLoginHandoff(value, 'wrong-key')).toBeNull()

    const invalid = await sealLoginHandoff(
      { b: 'https://tb.example.com', s: 'not-a-tool-bridge-key', exp: 9999999999 },
      SECRET,
    )
    expect(await openLoginHandoff(invalid, SECRET)).toBeNull()
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

describe('bindMeegoIdentity(open_id → union_id → user_key,best-effort)', () => {
  const base = (over: Partial<MeegoBindDeps>): MeegoBindDeps => ({
    loginOpenIdToUnionId: async openId => (openId === 'ou_target' ? 'on_union_target' : null),
    queryUserKeyByUnionId: async unionId => (unionId === 'on_union_target' ? 'uk2' : null),
    getMeegoUserKeys: async () => ({ existing: 'ukX' }),
    setMeegoUserKeys: async () => {},
    ...over,
  })

  it('open_id → union_id → user_key 全通 → 绑定并合并写回', async () => {
    let written: Record<string, string> | undefined
    const deps = base({
      setMeegoUserKeys: async (next) => {
        written = next
      },
    })
    const r = await bindMeegoIdentity(deps, 'newKeyId', 'ou_target')
    expect(r).toEqual({ bound: true, userKey: 'uk2' })
    expect(written).toEqual({ existing: 'ukX', newKeyId: 'uk2' }) // 合并,不覆盖已有
  })

  it('open_id 转 union_id 失败 → 不绑定(登录 app 无通讯录权限场景)', async () => {
    const r = await bindMeegoIdentity(base({ loginOpenIdToUnionId: async () => null }), 'k', 'ou_x')
    expect(r.bound).toBe(false)
  })

  it('union_id 查不到 meego 成员 → 不绑定(此人不在空间)', async () => {
    const deps = base({ queryUserKeyByUnionId: async () => null })
    const r = await bindMeegoIdentity(deps, 'k', 'ou_target')
    expect(r.bound).toBe(false)
  })

  it('任何环节抛错 → 吞掉返回 bound:false,不阻断', async () => {
    const deps = base({
      loginOpenIdToUnionId: async () => { throw new Error('meego down') },
    })
    const r = await bindMeegoIdentity(deps, 'k', 'ou_x')
    expect(r).toEqual({ bound: false, reason: 'meego down' })
  })
})
