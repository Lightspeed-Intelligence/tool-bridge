#!/usr/bin/env node
// 逐个实调 mcp/tipsy 下全部工具,报告 OK / FAIL。
// 用法: TB_KEY=<sk> node scripts/smoke-tipsy-tools.mjs [--only <substr>]
const BASE = process.env.TB_BASE_URL || 'https://tool-bridge.fantacy.live'
const NODE = 'mcp/tipsy'
const PREFIX = 'tipsy-analytics__'
const SK = process.env.TB_KEY || process.env.TB_SK
if (!SK) {
  console.error('need TB_KEY')
  process.exit(2)
}

const REPO = 'lightspeed-intelligence/tipsy-backend'
const DS = process.env.SMOKE_DS || '20260801'
const TOPIC = 'tb-smoke-allTools'

// 每个工具一组「应当成功」的参数。注释说明为何这样选。
const CASES = [
  // ---- MySQL ----
  ['mysql_list_tables', {}],
  ['mysql_describe_table', { table: 'wallet' }],
  ['mysql_query', { sql: 'SELECT COUNT(*) AS n FROM wallet' }],
  // ---- Lindorm ----
  ['lindorm_list_tables', {}],
  ['lindorm_describe_table', { table: 'gem_bill_v2' }],
  // 只取 1 行,避开全表扫描
  ['lindorm_query', { sql: 'SELECT * FROM gem_bill_v2 LIMIT 1' }],
  // ---- MaxCompute(分区表必带分区谓词)----
  ['maxcompute_list_tables', {}],
  ['maxcompute_describe_table', { table: 'dws_user_retention_daily' }],
  ['maxcompute_query', { sql: `SELECT ds, COUNT(*) AS n FROM dws_user_retention_daily WHERE ds='${DS}' GROUP BY ds` }],
  // ---- Quick Track ----
  ['qt_list_events', { ds: DS, keyword: 'pay' }],
  ['qt_event_fields', { event: 'payment_success', ds: DS }],
  // ---- SLS ----
  ['sls_list_logstores', {}],
  ['sls_query_logs', { logstore: 'tipsy-chat', query: '*', minutes_ago: 15, limit: 2 }],
  // ---- GitHub(git/ctags 依赖)----
  ['github_list_allowed_repos', {}],
  ['github_list_files', { repo: REPO, path: 'cmd/account_deletion_task' }],
  ['github_read_file', { repo: REPO, path: 'go.mod', max_bytes: 4000 }],
  ['github_grep', { repo: REPO, pattern: 'gem_bill_v2', limit: 5 }],
  ['github_git_log', { repo: REPO, limit: 3 }],
  ['github_git_blame', { repo: REPO, path: 'go.mod', line_start: 1, line_end: 5 }],
  // git_show 需要真实 sha —— 运行时由 git_log 结果回填
  ['github_git_show', { repo: REPO, sha: '__FROM_LOG__' }],
  ['github_git_diff', { repo: REPO, base: 'HEAD~1', head: 'HEAD', path: 'go.mod' }],
  ['github_symbol_search', { repo: REPO, name: 'main' }],
  // ---- 飞书 ----
  // 默认用一篇已确认「For Agent Read Docs 应用已在其知识空间内」的 wiki 文档。
  // 换别的文档若报 403(code=1770032),那是文档级 ACL,不是工具坏了 —— 把 bot
  // ou_94f34e3d0456e16eebe66e5cbd5c572e 加为协作者/知识空间成员即可。
  ['feishu_read_doc', {
    url_or_token: process.env.SMOKE_FEISHU_DOC
      || 'https://awaken-intelligence.feishu.cn/wiki/MgJEwFPi3ipNKik0viicqh9PnHd',
  }],
  // ---- 导出(必须排在 excel_* 之前:excel 用例读的就是这里生成的文件)----
  ['export_export_rows', { rows_json: JSON.stringify([{ user_id: 1, name: 'x' }, { user_id: 2, name: 'y' }]), path: '/tmp/tb_smoke_rows.xlsx' }],
  // export_result 需要真实结果句柄 —— 运行时由 mysql_query 回填
  ['export_export_result', { handle: '__FROM_QUERY__', path: '/tmp/tb_smoke_result.xlsx' }],
  // ---- Excel(读上一步 export 出来的真实 xlsx)----
  ['excel_list_sheets', { path: '__GENERATED_XLSX__' }],
  ['excel_preview_sheet', { path: '__GENERATED_XLSX__', rows: 5 }],
  ['excel_extract_column', { path: '__GENERATED_XLSX__', column: 'user_id' }],
  // ---- 工作纸 ----
  ['notes_record_finding', { topic: TOPIC, finding: 'smoke: 全工具实调' }],
  ['notes_read_findings', { topic: TOPIC }],
]

async function call(tool, args, timeoutMs = 300000) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const r = await fetch(`${BASE}/${NODE}/${PREFIX}${tool}`, {
      method: 'POST',
      headers: { 'authorization': `Bearer ${SK}`, 'content-type': 'application/json' },
      body: JSON.stringify(args),
      signal: ctrl.signal,
    })
    const text = await r.text()
    return { status: r.status, text }
  } catch (e) {
    return { status: 0, text: `LOCAL_ERROR: ${e.message}` }
  } finally { clearTimeout(t) }
}

// 工具返回的是 markdown 字符串;失败会以 ❌ 或 "Input validation error" 开头。
function verdict(status, text) {
  if (status === 0) return ['FAIL', text.slice(0, 200)]
  if (status >= 400) return ['FAIL', `HTTP ${status}: ${text.slice(0, 200)}`]
  const bad = ['❌', 'Input validation error', '"code":"', 'Traceback']
  for (const b of bad) if (text.includes(b)) return ['FAIL', text.replace(/\s+/g, ' ').slice(0, 260)]
  return ['OK', text.replace(/\s+/g, ' ').slice(0, 110)]
}

const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : null

const results = []
let shaFromLog = null
let handleFromQuery = null
let generatedXlsx = null

for (const [tool, argsTpl] of CASES) {
  if (only && !tool.includes(only)) continue
  let args = JSON.parse(JSON.stringify(argsTpl))

  // 运行时回填依赖
  if (args.sha === '__FROM_LOG__') {
    if (!shaFromLog) {
      results.push([tool, 'SKIP', 'no sha captured from git_log'])
      continue
    }
    args.sha = shaFromLog
  }
  if (args.handle === '__FROM_QUERY__') {
    if (!handleFromQuery) {
      results.push([tool, 'SKIP', 'no handle captured'])
      continue
    }
    args.handle = handleFromQuery
  }
  if (args.path === '__GENERATED_XLSX__') {
    if (!generatedXlsx) {
      results.push([tool, 'SKIP', 'no xlsx generated yet'])
      continue
    }
    args.path = generatedXlsx
  }
  if (args.url_or_token === '__SKIP__') {
    results.push([tool, 'SKIP', 'set SMOKE_FEISHU_DOC=<飞书链接> 才能实调'])
    continue
  }

  process.stderr.write(`→ ${tool} ... `)
  const { status, text } = await call(tool, args)
  const [v, note] = verdict(status, text)
  process.stderr.write(`${v}\n`)
  results.push([tool, v, note])

  // 捕获后续用例需要的运行时值
  if (v === 'OK' && tool === 'github_git_log') {
    const m = text.match(/\|\s*([0-9a-f]{12})\s*\|/)
    if (m) shaFromLog = m[1]
  }
  if (v === 'OK' && tool === 'mysql_query') {
    const m = text.match(/结果句柄 `(r\d+)`/)
    if (m) handleFromQuery = m[1]
  }
  if (v === 'OK' && tool === 'export_export_rows') {
    const m = text.match(/(\/[^\s`\\"]+\.xlsx)/)
    if (m) generatedXlsx = m[1]
  }
}

const ok = results.filter(r => r[1] === 'OK').length
const fail = results.filter(r => r[1] === 'FAIL')
const skip = results.filter(r => r[1] === 'SKIP')

console.log(`\n=== ${ok} OK / ${fail.length} FAIL / ${skip.length} SKIP (共 ${results.length}) ===\n`)
for (const [t, v, n] of results) console.log(`${v.padEnd(4)} ${t.padEnd(30)} ${n}`)
if (fail.length) {
  console.log('\n--- FAILURES ---')
  for (const [t, , n] of fail) console.log(`\n[${t}]\n${n}`)
}
process.exit(fail.length ? 1 : 0)
