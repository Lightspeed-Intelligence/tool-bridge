/**
 * SK 生命周期状态的派生与展示格式化。
 *
 * 抽到 lib 是因为 admin 面(system/sk)与自助面(system/my-keys)必须用**同一套**判据:
 * 两处各写一份的话,同一把 key 会在两个页面显示不同状态。判据与 core 的 `isKeyActive`
 * 对齐:disabled 优先,其次 expiresAt 已过视同失效。
 */

/** 只用于展示;真正的鉴权判定在服务端。 */
export type SkStatus = 'active' | 'disabled' | 'expired'

export function getSkStatus(
  key: { disabled?: boolean, expiresAt?: string },
  now: number,
): SkStatus {
  if (key.disabled) return 'disabled'
  if (key.expiresAt !== undefined && Date.parse(key.expiresAt) <= now) return 'expired'
  return 'active'
}

/** 短日期(列表用);不可解析时原样回显,避免把 "Invalid Date" 摆给用户。 */
export function formatSkDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}
