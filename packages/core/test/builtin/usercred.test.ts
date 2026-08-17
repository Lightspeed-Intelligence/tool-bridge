import { beforeEach, describe, expect, it } from 'vitest'
import type { BuiltinModule } from '../../src/builtin/types'
import type { CallContext } from '../../src/types'
import { createUserCredModule, resolveUserCredential } from '../../src/builtin/usercred'
import { base64urlEncode, SecretStoreImpl } from '../../src/secret/secretStore'
import { createSecretModule } from '../../src/builtin/secret'
import { MemoryStateStore } from '../../src/store'
import { isTBError } from '../../src/errors'

const NOW = '2026-08-12T00:00:00.000Z'
const alice: CallContext = { keyId: 'ka', owner: 'user:ou_alice', scopes: [], traceId: 't' }
const bob: CallContext = { keyId: 'kb', owner: 'user:ou_bob', scopes: [], traceId: 't' }

// 纯 WebCrypto:core tsconfig 不含 DOM 类型,补最小声明。
declare const crypto: { getRandomValues(array: Uint8Array): Uint8Array }

function makeMasterKey(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
}

describe('builtin usercred 模块(个人凭证,per-owner)', () => {
  let store: MemoryStateStore
  let secrets: SecretStoreImpl
  let mod: BuiltinModule

  beforeEach(() => {
    store = new MemoryStateStore()
    secrets = new SecretStoreImpl(store, makeMasterKey())
    mod = createUserCredModule(secrets, () => NOW)
  })

  it('help():set/list/delete 为 call,domains 为 read;无 admin', () => {
    const help = mod.help('system/usercred')
    expect(help.cmds.map(c => c.name).sort()).toEqual(['delete', 'domains', 'list', 'set'])
    const scopeOf = (name: string) => help.cmds.find(c => c.name === name)?.scope
    expect(['set', 'list', 'delete'].map(scopeOf)).toEqual(['call', 'call', 'call'])
    expect(scopeOf('domains')).toBe('read')
    expect(help.cmds.some(c => c.scope === 'admin')).toBe(false)
  })

  it('set 不回显 value;list 只出 domain+updatedAt;resolveUserCredential 能取回', async () => {
    const TOKEN = 'personal-yunxiao-pat-xyz'
    const ack = await mod.dispatch('set', { domain: 'yunxiao', value: TOKEN }, alice)
    expect(JSON.stringify(ack)).not.toContain(TOKEN)

    const page = (await mod.dispatch('list', {}, alice)) as {
      items: Array<{ domain: string, updatedAt: string }>
    }
    expect(page.items).toEqual([{ domain: 'yunxiao', updatedAt: NOW }])
    expect(Object.keys(page.items[0] ?? {}).sort()).toEqual(['domain', 'updatedAt'])

    expect(await resolveUserCredential(secrets, 'user:ou_alice', 'yunxiao')).toBe(TOKEN)
    // 落盘不含明文可读态。
    expect(JSON.stringify((await store.list('')).items)).not.toContain(TOKEN)
  })

  it('owner 取自 ctx:alice 与 bob 互不可见、互不可删', async () => {
    await mod.dispatch('set', { domain: 'yunxiao', value: 'alice-tok' }, alice)
    await mod.dispatch('set', { domain: 'yunxiao', value: 'bob-tok' }, bob)

    const aList = (await mod.dispatch('list', {}, alice)) as { items: Array<{ domain: string }> }
    expect(aList.items.map(i => i.domain)).toEqual(['yunxiao'])
    // 各自解析到各自的 token。
    expect(await resolveUserCredential(secrets, 'user:ou_alice', 'yunxiao')).toBe('alice-tok')
    expect(await resolveUserCredential(secrets, 'user:ou_bob', 'yunxiao')).toBe('bob-tok')

    // bob 删自己的,不影响 alice。
    await mod.dispatch('delete', { domain: 'yunxiao' }, bob)
    expect(await resolveUserCredential(secrets, 'user:ou_alice', 'yunxiao')).toBe('alice-tok')
    expect(await resolveUserCredential(secrets, 'user:ou_bob', 'yunxiao')).toBeUndefined()
  })

  it('domain 含 : → invalid_argument(防越权拼保留名)', async () => {
    await expect(
      mod.dispatch('set', { domain: 'plugin-token:meego', value: 'x' }, alice),
    ).rejects.toSatisfy(e => isTBError(e) && e.code === 'invalid_argument')
  })

  it('未知 cmd → invalid_argument', async () => {
    await expect(mod.dispatch('resolve', { domain: 'yunxiao' }, alice)).rejects.toSatisfy(
      e => isTBError(e) && e.code === 'invalid_argument',
    )
  })

  it('domains cmd:可配域 ⋈ 本人已配状态;listDomains 缺省则只回已配', async () => {
    // 注入两个可配域,alice 只配了 yunxiao。
    const withList = createUserCredModule(secrets, () => NOW, async () => [
      { domain: 'yunxiao', nodePaths: ['mcp/yunxiao'], description: '云效' },
      { domain: 'github', nodePaths: ['mcp/gh'] },
    ])
    await withList.dispatch('set', { domain: 'yunxiao', value: 'alice-pat' }, alice)
    const page = (await withList.dispatch('domains', {}, alice)) as {
      items: Array<{ configured: boolean, domain: string, nodePaths: string[] }>
    }
    const byDomain = Object.fromEntries(page.items.map(i => [i.domain, i]))
    expect(byDomain.yunxiao?.configured).toBe(true)
    expect(byDomain.yunxiao?.nodePaths).toEqual(['mcp/yunxiao'])
    expect(byDomain.github?.configured).toBe(false)

    // listDomains 缺省(纯 secret 模块,独立 store)→ domains 只回本人已配的域(孤儿也列出便于清理)。
    const bareStore = new MemoryStateStore()
    const bareSecrets = new SecretStoreImpl(bareStore, makeMasterKey())
    const bareMod = createUserCredModule(bareSecrets, () => NOW)
    await bareMod.dispatch('set', { domain: 'orphan', value: 'x' }, alice)
    const bare = (await bareMod.dispatch('domains', {}, alice)) as {
      items: Array<{ configured: boolean, domain: string }>
    }
    expect(bare.items).toEqual([{ domain: 'orphan', nodePaths: [], configured: true, updatedAt: NOW }])
  })

  it('admin 面 system/secret 的 list 不泄露 usercred: 条目', async () => {
    await mod.dispatch('set', { domain: 'yunxiao', value: 'alice-tok' }, alice)
    const secretMod = createSecretModule(secrets, () => NOW)
    await secretMod.dispatch('set', { name: 'yunxiao', value: 'admin-default' }, {
      ...alice,
      owner: 'user:admin',
    })
    const page = (await secretMod.dispatch('list', {}, alice)) as {
      items: Array<{ name: string }>
    }
    expect(page.items.some(i => i.name.startsWith('usercred:'))).toBe(false)
    expect(page.items.map(i => i.name)).toContain('yunxiao')
  })
})
