import { MemoryStateStore } from '@tool-bridge/core'
import { describe, expect, it } from 'vitest'
import { revokeDelegationGrantsFor } from '../src/oauthDelegation'

const REFRESH_PREFIX = 'oauth:refresh:'
const ALICE = 'user:ou_alice'
const BOB = 'user:ou_bob'

function grant(clientId: string, subject: string): unknown {
  return {
    version: 1,
    clientId,
    subject,
    grantNames: ['mcp.call'],
    expiresAt: Math.floor(Date.UTC(2027, 0, 1) / 1000),
  }
}

describe('revokeDelegationGrantsFor(自助撤销委托 key 的连带清理)', () => {
  it('清掉本人授予该 client 的 refresh token', async () => {
    const store = new MemoryStateStore()
    await store.put(`${REFRESH_PREFIX}h1`, grant('client-42', ALICE))

    await revokeDelegationGrantsFor(store, ALICE, 'oauth-access:client-42')
    expect(await store.get(`${REFRESH_PREFIX}h1`)).toBeNull()
  })

  it('不误删他人的、或其他 client 的授权', async () => {
    const store = new MemoryStateStore()
    await store.put(`${REFRESH_PREFIX}mine`, grant('client-42', ALICE))
    await store.put(`${REFRESH_PREFIX}other-user`, grant('client-42', BOB))
    await store.put(`${REFRESH_PREFIX}other-client`, grant('client-99', ALICE))

    await revokeDelegationGrantsFor(store, ALICE, 'oauth-access:client-42')

    expect(await store.get(`${REFRESH_PREFIX}mine`)).toBeNull()
    // 他人的、以及同一人授予别的 client 的,都必须留着。
    expect(await store.get(`${REFRESH_PREFIX}other-user`)).toBeDefined()
    expect(await store.get(`${REFRESH_PREFIX}other-client`)).toBeDefined()
  })

  it('同一 client 的多把 refresh token 全部清掉', async () => {
    const store = new MemoryStateStore()
    await store.put(`${REFRESH_PREFIX}a`, grant('client-42', ALICE))
    await store.put(`${REFRESH_PREFIX}b`, grant('client-42', ALICE))

    await revokeDelegationGrantsFor(store, ALICE, 'oauth-access:client-42')
    expect(await store.get(`${REFRESH_PREFIX}a`)).toBeNull()
    expect(await store.get(`${REFRESH_PREFIX}b`)).toBeNull()
  })

  it('description 不是委托前缀 / clientId 为空 → 什么都不动', async () => {
    const store = new MemoryStateStore()
    await store.put(`${REFRESH_PREFIX}h1`, grant('client-42', ALICE))

    await revokeDelegationGrantsFor(store, ALICE, 'self-issued · cli')
    await revokeDelegationGrantsFor(store, ALICE, 'oauth-access:')
    expect(await store.get(`${REFRESH_PREFIX}h1`)).toBeDefined()
  })

  it('畸形记录不致命(跳过,继续清理其余)', async () => {
    const store = new MemoryStateStore()
    await store.put(`${REFRESH_PREFIX}bad`, { nope: true })
    await store.put(`${REFRESH_PREFIX}good`, grant('client-42', ALICE))

    await revokeDelegationGrantsFor(store, ALICE, 'oauth-access:client-42')
    expect(await store.get(`${REFRESH_PREFIX}good`)).toBeNull()
    expect(await store.get(`${REFRESH_PREFIX}bad`)).toBeDefined()
  })
})
