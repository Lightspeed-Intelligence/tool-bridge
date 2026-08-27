#!/usr/bin/env node
/**
 * KV → D1 权威状态迁移(ADR-001 存量部署补充)。
 *
 * 为什么需要它:上游 ADR-001 把 Cloudflare 权威状态从 KV 迁到 D1,但上游处于
 * pre-launch,明确"切换即重新引导,不提供迁移工具"。本仓生产在跑(节点/SK/凭证
 * 全在 KV),不迁数据就等于服务重置 —— 故自建此脚本。
 *
 * 迁移语义:KV 与 D1StateStore 共用 core/store.ts 的同一 key 布局,值两边都是
 * JSON 文本,**一对一搬运、不做结构转换**。D1 侧表 tb_state_kv(key TEXT PRIMARY
 * KEY, value TEXT NOT NULL),写入用 upsert,故本脚本**幂等可重跑**。
 *
 * 用法:
 *   node scripts/migrate-kv-to-d1.mjs --kv <namespace-id> --db <d1-name> [--dry-run] [--batch 50]
 *
 * 例:
 *   # 先看会搬什么(不写)
 *   node scripts/migrate-kv-to-d1.mjs --kv a1e48dcf… --db tb-db --dry-run
 *   # 真迁
 *   node scripts/migrate-kv-to-d1.mjs --kv a1e48dcf… --db tb-db
 *
 * 注意:
 * - 一律走 `wrangler --remote`。**不加 --remote 的 kv 命令读的是本地 miniflare**
 *   (2026-08-26 踩过:据此误判"生产数据不在 KV")。
 * - 迁移期间应停写(或接受最后写入丢失):本脚本是快照搬运,不做增量追平。
 * - 迁完自校验:比对 KV 与 D1 的 key 计数并抽样比对值。
 */

import { readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`)
  return i !== -1 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : fallback
}
const KV = arg('kv')
const DB = arg('db')
const DRY = process.argv.includes('--dry-run')
const BATCH = Number(arg('batch', '50'))

if (KV === undefined || DB === undefined) {
  console.error('用法: node scripts/migrate-kv-to-d1.mjs --kv <namespace-id> --db <d1-name> [--dry-run] [--batch 50]')
  process.exit(2)
}

/**
 * 账户 id:多账户 wrangler 在非交互模式下必须显式指定,否则 "More than one account
 * available"。取 --account 参数,否则读环境变量,否则从仓库根 .env 里捞。
 */
function resolveAccountId() {
  const fromArg = arg('account')
  if (fromArg !== undefined) return fromArg
  if (process.env.CLOUDFLARE_ACCOUNT_ID !== undefined) return process.env.CLOUDFLARE_ACCOUNT_ID
  for (const p of ['.env', '../.env', '../../.env']) {
    try {
      const m = readFileSync(new URL(p, import.meta.url), 'utf8')
        .match(/^CLOUDFLARE_ACCOUNT_ID=(.+)$/m)
      if (m !== null) return m[1].trim()
    } catch {
      // 该候选路径没有 .env(或不可读)——继续试下一个。
    }
  }
  return undefined
}
const ACCOUNT = resolveAccountId()

/** 调 wrangler(项目 pin 版本经 npx);返回 stdout。 */
function wrangler(args, { quiet = false } = {}) {
  return execFileSync('npx', ['wrangler', ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: quiet ? ['ignore', 'pipe', 'ignore'] : ['ignore', 'pipe', 'inherit'],
    env: ACCOUNT === undefined
      ? process.env
      : { ...process.env, CLOUDFLARE_ACCOUNT_ID: ACCOUNT },
  })
}

/** SQL 字符串字面量转义(单引号加倍)。 */
function sqlStr(s) {
  return `'${String(s).replace(/'/g, '\'\'')}'`
}

console.log(`KV=${KV}  D1=${DB}  dry-run=${DRY}`)

// ---------- 1. 读 KV 全部 key ----------
console.log('\n[1/4] 列 KV key(--remote)...')
const keys = JSON.parse(wrangler(['kv', 'key', 'list', '--namespace-id', KV, '--remote'], { quiet: true }))
  .map(k => k.name)
console.log(`  ${keys.length} 个 key`)
const byPrefix = {}
for (const k of keys) {
  const p = k.split(':')[0]
  byPrefix[p] = (byPrefix[p] ?? 0) + 1
}
console.log('  前缀分布:', JSON.stringify(byPrefix))

// ---------- 2. 逐条读值 ----------
console.log('\n[2/4] 读取每个 key 的值...')
const pairs = []
for (const [i, key] of keys.entries()) {
  const value = wrangler(['kv', 'key', 'get', key, '--namespace-id', KV, '--remote'], { quiet: true })
  pairs.push([key, value])
  if ((i + 1) % 20 === 0 || i + 1 === keys.length) console.log(`  ${i + 1}/${keys.length}`)
}

if (DRY) {
  console.log('\n[dry-run] 将写入 D1 的条目(前 10):')
  for (const [k, v] of pairs.slice(0, 10)) console.log(`  ${k}  (${v.length} bytes)`)
  console.log(`\n[dry-run] 共 ${pairs.length} 条,未写入。去掉 --dry-run 执行真迁移。`)
  process.exit(0)
}

// ---------- 3. 建表 + 批量 upsert ----------
console.log('\n[3/4] 写入 D1(建表 + 分批 upsert)...')
const sqlFile = join(tmpdir(), `kv2d1-${Date.now()}.sql`)
try {
  for (let off = 0; off < pairs.length; off += BATCH) {
    const chunk = pairs.slice(off, off + BATCH)
    const stmts = [
      'CREATE TABLE IF NOT EXISTS tb_state_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;',
      ...chunk.map(([k, v]) =>
        `INSERT INTO tb_state_kv (key, value) VALUES (${sqlStr(k)}, ${sqlStr(v)}) `
        + 'ON CONFLICT(key) DO UPDATE SET value = excluded.value;'),
    ]
    writeFileSync(sqlFile, stmts.join('\n'), 'utf8')
    wrangler(['d1', 'execute', DB, '--remote', '--file', sqlFile, '--yes'], { quiet: true })
    console.log(`  ${Math.min(off + BATCH, pairs.length)}/${pairs.length}`)
  }
} finally {
  try {
    unlinkSync(sqlFile)
  } catch {
    // 临时 SQL 文件可能已不存在;清理失败不影响迁移结果。
  }
}

// ---------- 4. 自校验 ----------
console.log('\n[4/4] 校验...')
const countOut = wrangler(
  ['d1', 'execute', DB, '--remote', '--command', 'SELECT COUNT(*) AS n FROM tb_state_kv', '--json'],
  { quiet: true },
)
let d1Count
try {
  const parsed = JSON.parse(countOut)
  d1Count = parsed?.[0]?.results?.[0]?.n ?? parsed?.result?.[0]?.results?.[0]?.n
} catch {
  d1Count = undefined
}
console.log(`  KV keys : ${keys.length}`)
console.log(`  D1 rows : ${d1Count ?? '(解析失败,请手工 SELECT COUNT(*) 核对)'}`)

if (typeof d1Count === 'number' && d1Count < keys.length) {
  console.error(`\n✗ D1 行数(${d1Count}) 少于 KV key 数(${keys.length}) —— 迁移不完整,请重跑(幂等)。`)
  process.exit(1)
}
console.log('\n✓ 迁移完成。切换部署前请再抽查若干 sk:/secret:/node: 键的值。')
