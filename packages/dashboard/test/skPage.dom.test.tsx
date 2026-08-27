/**
 * SK 页的**渲染分流**回归。
 *
 * 这一层测不掉的东西正是本次改动最容易错的:非 admin 读 admin 面拿 404,那是**预期结果**
 * 而不是错误 —— 一旦被当成错误,普通用户每次进页面都会看到一片红。纯逻辑测不到这个
 * (它是"哪些区域被挂载"的性质),所以放在 dom project 里。
 */

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { MyKeyInfo } from '@/lib/types'

const MY_KEY: MyKeyInfo = {
  id: 'mk-1',
  owner: 'user:alice',
  scopes: [{ pattern: 'mcp/**', actions: ['read', 'call'] }],
  copyable: true,
  origin: 'self',
  // 服务端已剥掉来源前缀,这里就是用户自己写的那段。
  description: '我的笔记本',
  createdAt: '2026-08-01T00:00:00.000Z',
}

const LEGACY_KEY: MyKeyInfo = {
  id: 'mk-legacy',
  owner: 'user:alice',
  scopes: [{ pattern: 'mcp/**', actions: ['read'] }],
  // 历史签发:只有 hash,明文永远取不回。
  copyable: false,
  origin: 'login',
  // 登录会话 key 没有用户描述(内部时间戳不该露给用户)。
  createdAt: '2026-07-01T00:00:00.000Z',
}

const adminState = { data: undefined as boolean | undefined, error: null as Error | null, isError: false }
const myKeysState = { data: [MY_KEY] as MyKeyInfo[] }
const skListItems: unknown[] = []

vi.mock('@/lib/queries', () => ({
  useInvalidate: () => vi.fn(async () => {}),
  useInvoke: () => ({ isPending: false, mutate: vi.fn(), mutateAsync: vi.fn(), reset: vi.fn() }),
  useIsAdmin: () => adminState,
  useMyKeys: () => ({
    data: myKeysState.data,
    error: null,
    isError: false,
    isPending: false,
    refetch: vi.fn(async () => ({})),
  }),
  useSkList: () => ({
    data: { items: skListItems },
    error: null,
    fetchNextPage: vi.fn(),
    hasNextPage: false,
    isError: false,
    isFetchingNextPage: false,
    isPending: false,
    refetch: vi.fn(async () => ({})),
  }),
}))

vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

const { SkPage } = await import('@/pages/system/SkPage')

afterEach(() => {
  cleanup()
  adminState.data = undefined
  adminState.error = null
  adminState.isError = false
  myKeysState.data = [MY_KEY]
})

describe('SkPage 的 admin 分流', () => {
  it('非 admin(探测被拒 → false):只有「我的 key」,不出现任何报错或 admin 区域', async () => {
    adminState.data = false
    render(<SkPage />)

    await waitFor(() => expect(screen.getByRole('region', { name: '我的 key' })).toBeTruthy())
    expect(screen.queryByText('全部 Secret Key（管理员）')).toBeNull()
    // 关键:预期的没权限不得渲染成任何错误面 —— 既没有 alert(错误态 EmptyState /
    // 表单报错),也没有那行「无法确认管理员权限」的 status 提示。
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.queryByText(/无法确认/)).toBeNull()
  })

  it('admin(探测成功 → true):两个区域同时在', async () => {
    adminState.data = true
    render(<SkPage />)

    await waitFor(() => expect(screen.getByText('全部 Secret Key（管理员）')).toBeTruthy())
    expect(screen.getByRole('region', { name: '我的 key' })).toBeTruthy()
  })

  it('探测尚未返回(undefined):不抢先渲染 admin 区域', async () => {
    adminState.data = undefined
    render(<SkPage />)

    await waitFor(() => expect(screen.getByRole('region', { name: '我的 key' })).toBeTruthy())
    expect(screen.queryByText('全部 Secret Key（管理员）')).toBeNull()
  })

  it('探测遇真故障(网络/5xx):提示一行,但自助面照常可用', async () => {
    adminState.data = undefined
    adminState.isError = true
    adminState.error = new Error('网关不可达')
    render(<SkPage />)

    await waitFor(() => expect(screen.getByRole('status')).toBeTruthy())
    expect(screen.getByRole('status').textContent).toContain('网关不可达')
    expect(screen.getByRole('region', { name: '我的 key' })).toBeTruthy()
  })
})

describe('「我的 key」的复制可用性', () => {
  it('copyable 的 key 可复制;历史 key 的复制按钮为禁用态并给出说明', async () => {
    adminState.data = false
    myKeysState.data = [MY_KEY, LEGACY_KEY]
    render(<SkPage />)

    await waitFor(() => expect(screen.getByLabelText('复制明文')).toBeTruthy())
    expect(screen.getByLabelText('复制明文').hasAttribute('disabled')).toBe(false)

    const legacy = screen.getByLabelText('无法取回明文')
    expect(legacy.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(/明文无法取回/)).toBeTruthy()
  })

  it('权限摘要显示人话而非 scope JSON', async () => {
    adminState.data = false
    render(<SkPage />)

    await waitFor(() => expect(screen.getByText('MCP 工具')).toBeTruthy())
    expect(screen.getByText('查看 · 调用')).toBeTruthy()
    expect(screen.getByText('我的笔记本')).toBeTruthy()
  })
})

describe('来源与描述的展示', () => {
  it('按 origin 显示徽标;不再依赖 description 前缀', async () => {
    adminState.data = false
    myKeysState.data = [MY_KEY, LEGACY_KEY]
    render(<SkPage />)

    await waitFor(() => expect(screen.getByText('我签发的')).toBeTruthy())
    expect(screen.getByText('登录会话')).toBeTruthy()
    // 存储层的来源前缀不该出现在页面上(它已由服务端剥掉)。
    expect(screen.queryByText(/self-issued|feishu-login|oauth-access/)).toBeNull()
  })

  it('登录会话 key 没有用户描述:显示占位而非内部时间戳', async () => {
    adminState.data = false
    myKeysState.data = [LEGACY_KEY]
    render(<SkPage />)

    await waitFor(() => expect(screen.getByText('浏览器登录会话')).toBeTruthy())
    expect(screen.queryByText(/2026-07-01T/)).toBeNull()
  })

  it('委托 key 的描述是 clientId,原样展示', async () => {
    adminState.data = false
    myKeysState.data = [{ ...MY_KEY, origin: 'delegation', description: 'my-app' }]
    render(<SkPage />)

    await waitFor(() => expect(screen.getByText('授权应用')).toBeTruthy())
    expect(screen.getByText('my-app')).toBeTruthy()
  })
})
