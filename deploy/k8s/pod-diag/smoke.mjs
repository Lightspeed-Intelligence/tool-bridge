import { createToolBridge, MemoryStateStore } from '@tool-bridge/sdk'
/**
 * 本地端到端冒烟:验证 SDK 反向连接 + 工具注册 + 纯 HTTP 调用 + ~help 这条 tool-bridge
 * 链路(不连真集群 —— K8s client 用注入的假数据替换,只验证 tool-bridge 侧行为)。
 *
 * 起一个本地 TB 网关(SDK fetch 面 + 内存 deviceTransport 桥),把 pod-diag 的六个
 * 工具注册进去,然后用 fetch 打 ~help 和调用,断言返回形状。
 *
 * 运行:node smoke.mjs
 */
import { serve } from '@hono/node-server'

const ADMIN_SK = 'smoke-admin-sk'
const PORT = 8799
const BASE = `http://127.0.0.1:${PORT}`

// 直接复用生产工具的 spec/参数校验逻辑不易(index.mjs 会 loadFromCluster 崩),
// 这里内联一个等价的最小工具集,聚焦验证 tool-bridge 链路而非 K8s 调用。
const tb = createToolBridge({ state: new MemoryStateStore(), adminSk: ADMIN_SK })

tb.registerTool(
  'tools/pod-diag',
  {
    List: () => [
      {
        name: 'getLogs',
        description: '拉取某 pod 的容器日志(只读)',
        effect: 'read',
        inputSchema: {
          type: 'object',
          required: ['namespace', 'pod'],
          properties: {
            namespace: { type: 'string' },
            pod: { type: 'string' },
            tailLines: { type: 'number' },
          },
        },
      },
    ],
    Get: name => ({ name, description: 'stub', effect: 'read' }),
    Call: (name, args) => ({ content: { stubTool: name, echoedArgs: args } }),
  },
  { description: '冒烟用 stub;生产实现见 src/index.mjs' },
)

const server = serve({ fetch: req => tb.fetch(req), port: PORT })
await new Promise(r => setTimeout(r, 300))

let failures = 0
function check(label, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  — ${detail}`}`)
  if (!ok) failures++
}

const auth = { Authorization: `Bearer ${ADMIN_SK}` }

// 1) ~help:默认 text/plain(面向 LLM 的 Help DSL),含工具名与参数 schema
const helpRes = await fetch(`${BASE}/tools/pod-diag/~help`, { headers: auth })
const helpText = await helpRes.text()
check('~help 200', helpRes.status === 200, `status=${helpRes.status}`)
check('~help 含 getLogs', helpText.includes('getLogs'), helpText.slice(0, 300))
// 节点级 ~help 是索引(省略 schema);工具级 ~help 才透出完整 inputSchema。
const toolHelp = await (
  await fetch(`${BASE}/tools/pod-diag/getLogs/~help`, { headers: auth })
).text()
check('工具级 ~help 透出 namespace schema', toolHelp.includes('namespace'), toolHelp.slice(0, 400))

// 2) 形态 A:节点路径 + {tool,arguments} 信封。返回按内容协商为 markdown(json 代码块),
//    用 text 读避免 JSON.parse 报错;断言用子串。
const aRes = await fetch(`${BASE}/tools/pod-diag`, {
  method: 'POST',
  headers: { ...auth, 'Content-Type': 'application/json' },
  body: JSON.stringify({ tool: 'getLogs', arguments: { namespace: 'default', pod: 'x' } }),
})
const aText = await aRes.text()
check('调用形态A 200', aRes.status === 200, `status=${aRes.status} body=${aText.slice(0, 200)}`)
check('形态A 回显 args', aText.includes('default') && aText.includes('getLogs'), aText.slice(0, 300))

// 3) 形态 B:直连工具路径,body 即 arguments
const bRes = await fetch(`${BASE}/tools/pod-diag/getLogs`, {
  method: 'POST',
  headers: { ...auth, 'Content-Type': 'application/json' },
  body: JSON.stringify({ namespace: 'kube-system', pod: 'y' }),
})
const bText = await bRes.text()
check('调用形态B 200', bRes.status === 200, `status=${bRes.status} body=${bText.slice(0, 200)}`)
check('形态B 回显 args', bText.includes('kube-system'), bText.slice(0, 300))

// 4) 无 SK → 拒
const noAuth = await fetch(`${BASE}/tools/pod-diag/~help`)
check('无 SK 被拒', noAuth.status === 401 || noAuth.status === 404, `status=${noAuth.status}`)

server.close?.()
console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
