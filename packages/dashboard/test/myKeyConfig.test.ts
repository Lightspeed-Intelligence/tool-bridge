import { describe, expect, it } from 'vitest'
import type { MyKeyInfo } from '../src/lib/types'
import {
  buildMyKeyCreateArgs,
  buildMyKeyUpdateArgs,
  describeScopes,
  INITIAL_MY_KEY_FORM,
  type MyKeyFormState,
  ORIGIN_LABEL,
  toMyKeyForm,
} from '../src/pages/system/forms/myKeyConfig'
import { getSkStatus } from '../src/lib/skStatus'

const form = (patch: Partial<MyKeyFormState>): MyKeyFormState => ({
  ...INITIAL_MY_KEY_FORM,
  ...patch,
})

const key = (patch: Partial<MyKeyInfo>): MyKeyInfo => ({
  id: 'k1',
  owner: 'user:alice',
  scopes: [],
  copyable: true,
  origin: 'self',
  createdAt: '2026-08-01T00:00:00.000Z',
  ...patch,
})

describe('my-key 有效期换算', () => {
  it('永久 = 不带 expiresAt 字段(而不是传空串)', () => {
    expect(buildMyKeyCreateArgs(form({ preset: 'forever' }))).toEqual({})
  })

  it('描述留空则不传;两侧空白被裁掉', () => {
    expect(buildMyKeyCreateArgs(form({ description: '   ' }))).toEqual({})
    expect(buildMyKeyCreateArgs(form({ description: '  笔记本 CLI  ' })))
      .toEqual({ description: '笔记本 CLI' })
  })

  it('预设天数按 ISO-8601 落地', () => {
    const now = Date.parse('2026-08-26T00:00:00.000Z')
    expect(buildMyKeyCreateArgs(form({ preset: '7d' }), now).expiresAt)
      .toBe('2026-09-02T00:00:00.000Z')
    expect(buildMyKeyCreateArgs(form({ preset: '30d' }), now).expiresAt)
      .toBe('2026-09-25T00:00:00.000Z')
    expect(buildMyKeyCreateArgs(form({ preset: '90d' }), now).expiresAt)
      .toBe('2026-11-24T00:00:00.000Z')
  })

  it('自定义日期取当地当天 23:59:59 —— 不能按 UTC 零点算,否则东八区当天上午就失效', () => {
    const now = Date.parse('2026-08-26T00:00:00.000Z')
    const iso = buildMyKeyCreateArgs(form({ preset: 'custom', customDate: '2026-09-01' }), now)
      .expiresAt
    const at = new Date(String(iso))
    expect(at.getFullYear()).toBe(2026)
    expect(at.getMonth()).toBe(8)
    expect(at.getDate()).toBe(1)
    expect(at.getHours()).toBe(23)
  })

  it('自定义日期非法 / 不存在 / 已过期都拦在前端', () => {
    const now = Date.parse('2026-08-26T00:00:00.000Z')
    expect(() => buildMyKeyCreateArgs(form({ preset: 'custom', customDate: '' }), now)).toThrow()
    expect(() => buildMyKeyCreateArgs(form({ preset: 'custom', customDate: '2026-02-30' }), now))
      .toThrow()
    expect(() => buildMyKeyCreateArgs(form({ preset: 'custom', customDate: '2020-01-01' }), now))
      .toThrow()
  })
})

describe('my-key update 入参', () => {
  it('改成永久必须显式传空串 —— 字段缺省在后端表示「不动」', () => {
    expect(buildMyKeyUpdateArgs('k1', form({ preset: 'forever' })))
      .toEqual({ id: 'k1', description: '', expiresAt: '' })
  })

  it('有过期时间时照常带 ISO 值', () => {
    const now = Date.parse('2026-08-26T00:00:00.000Z')
    const args = buildMyKeyUpdateArgs('k1', form({ preset: '7d', description: 'x' }), now)
    expect(args).toEqual({ id: 'k1', description: 'x', expiresAt: '2026-09-02T00:00:00.000Z' })
  })
})

describe('来源徽标', () => {
  it('四种 origin 都有中文文案 —— 后端新增取值时这里会漏,故逐个钉住', () => {
    expect(ORIGIN_LABEL).toEqual({
      self: '我签发的',
      login: '登录会话',
      delegation: '授权应用',
      other: '其它来源',
    })
  })
})

describe('编辑表单初值', () => {
  it('description 直接用(服务端已剥好前缀);永久 key → forever', () => {
    expect(toMyKeyForm(key({ description: '我的笔记本' })))
      .toEqual({ description: '我的笔记本', preset: 'forever', customDate: '' })
  })

  it('description 缺失(如登录会话 key)按空处理,不写出 undefined', () => {
    expect(toMyKeyForm(key({ origin: 'login' })))
      .toEqual({ description: '', preset: 'forever', customDate: '' })
  })

  it('有过期时间 → 落到自定义日期便于原地微调', () => {
    const dated = toMyKeyForm(key({ expiresAt: '2027-01-05T12:00:00.000Z' }))
    expect(dated.preset).toBe('custom')
    expect(dated.customDate).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })
})

describe('权限摘要', () => {
  it('pattern 与 action 都换成人话,原始 glob 保留备查', () => {
    const lines = describeScopes([
      { pattern: 'mcp/**', actions: ['read', 'call'] },
      { pattern: 'system/my-keys', actions: ['read', 'call'] },
      { pattern: 'secret/**', actions: ['admin'], effect: 'deny' },
    ])
    expect(lines[0]).toEqual({
      pattern: 'mcp/**',
      label: 'MCP 工具',
      actions: '查看 · 调用',
      deny: false,
    })
    expect(lines[1]?.label).toBe('我的密钥')
    // 未知 pattern 回落到 glob 本身,不至于显示空白。
    expect(lines[2]?.label).toBe('secret/**')
    expect(lines[2]?.deny).toBe(true)
  })
})

describe('SK 状态判据(admin 面与自助面共用)', () => {
  const now = Date.parse('2026-08-26T00:00:00.000Z')

  it('disabled 优先于过期;过期视同失效;否则有效', () => {
    expect(getSkStatus({ disabled: true, expiresAt: '2099-01-01T00:00:00.000Z' }, now))
      .toBe('disabled')
    expect(getSkStatus({ expiresAt: '2026-08-25T00:00:00.000Z' }, now)).toBe('expired')
    expect(getSkStatus({ expiresAt: '2026-08-27T00:00:00.000Z' }, now)).toBe('active')
    expect(getSkStatus({}, now)).toBe('active')
  })
})
