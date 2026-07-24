/**
 * tb-pod-diag —— 集群内只读诊断服务。
 *
 * 设计底线(与前序讨论一致):
 *   - 只暴露【结构性只读】的 K8s 查询:listPods / getLogs / describePod /
 *     getPodStatus / getEvents。没有 shell、没有 exec、没有 kubectl 二进制。
 *   - 授权面 = RBAC 授予本 SA 的只读子资源(pods / pods/log / events,get/list)。
 *     即便本进程被攻破,SA token 也只能读,偷不到任何写/exec 能力。
 *   - namespace 边界由 ALLOWED_NAMESPACES 环境变量声明(逗号分隔);工具入参里的
 *     namespace 必须落在白名单内,否则拒。这是【应用层】收敛,真正的硬边界仍是 RBAC
 *     用 Role(限 ns)而非 ClusterRole —— 两者叠加,纵深防御。
 *   - 经 @tool-bridge/sdk 反向连接到网关,把本地函数挂到远程树 tools/pod-diag。
 *     SA token 只在本 pod 内,不经 Agent、不经网关。
 *
 * 环境变量:
 *   TB_BASE_URL           网关 base url(https)
 *   TB_SK                 一把 scope 只含 device 注册权的 SK
 *   TB_DEVICE_ID          稳定设备 id(缺省 pod-diag)
 *   ALLOWED_NAMESPACES    逗号分隔的允许查询的 namespace(必填;不设=拒一切)
 *   MAX_TAIL_LINES        getLogs tailLines 上限(缺省 2000)
 */

import { createToolBridge, MemoryStateStore, TBError } from '@tool-bridge/sdk'
import { CoreV1Api, KubeConfig } from '@kubernetes/client-node'

function requireEnv(name) {
  const v = process.env[name]
  if (!v || v.trim() === '') {
    console.error(`[pod-diag] 缺少必填环境变量 ${name}`)
    process.exit(1)
  }
  return v.trim()
}

const BASE_URL = requireEnv('TB_BASE_URL')
const SK = requireEnv('TB_SK')
const DEVICE_ID = process.env.TB_DEVICE_ID?.trim() || 'pod-diag'
const MAX_TAIL_LINES = Number(process.env.MAX_TAIL_LINES ?? 2000)

/** 允许查询的 namespace 白名单;空集 = 拒一切(默认拒,和 shell 白名单同哲学)。 */
const ALLOWED_NS = new Set(
  (process.env.ALLOWED_NAMESPACES ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean),
)
if (ALLOWED_NS.size === 0) {
  console.error('[pod-diag] ALLOWED_NAMESPACES 为空 —— 拒绝一切查询。请显式声明允许的 namespace。')
}

// in-cluster 装配:自动读取挂载的 SA token + CA + APIServer 地址。
const kc = new KubeConfig()
kc.loadFromCluster()
const core = kc.makeApiClient(CoreV1Api)

/** namespace 守卫:入参 ns 必须在白名单内,否则 permission_denied。 */
function assertNamespace(ns) {
  if (typeof ns !== 'string' || ns.trim() === '') {
    throw new TBError('invalid_argument', 'namespace 必填')
  }
  if (!ALLOWED_NS.has(ns)) {
    throw new TBError(
      'permission_denied',
      `namespace '${ns}' 不在允许列表内;允许:${[...ALLOWED_NS].join(', ') || '(空)'}`,
    )
  }
  return ns
}

/** 提取 K8s client 错误里对人有用的信息(状态码 + message),避免把整个响应体外泄。 */
function wrapK8sError(err) {
  const code = err?.statusCode ?? err?.response?.statusCode
  const msg = err?.body?.message ?? err?.message ?? String(err)
  if (code === 403) return new TBError('permission_denied', `APIServer 拒绝(RBAC 不足):${msg}`)
  if (code === 404) return new TBError('not_found', msg)
  return new TBError('internal', `K8s 调用失败:${msg}`)
}

function str(args, key, required = false) {
  const v = args?.[key]
  if (v === undefined || v === null || v === '') {
    if (required) throw new TBError('invalid_argument', `${key} 必填`)
    return undefined
  }
  if (typeof v !== 'string') throw new TBError('invalid_argument', `${key} 必须是字符串`)
  return v
}

function num(args, key) {
  const v = args?.[key]
  if (v === undefined || v === null) return undefined
  const n = Number(v)
  if (!Number.isFinite(n)) throw new TBError('invalid_argument', `${key} 必须是数字`)
  return n
}

// ── 六个只读工具 ────────────────────────────────────────────────
const TOOLS = {
  listPods: {
    spec: {
      description: '列出某 namespace 下的 pod(名称/阶段/就绪/重启数/节点)',
      effect: 'read',
      inputSchema: {
        type: 'object',
        required: ['namespace'],
        properties: {
          namespace: { type: 'string', description: '目标 namespace(须在允许列表内)' },
          labelSelector: { type: 'string', description: '标签选择器,如 app=web(可选)' },
        },
      },
    },
    async call(args) {
      const ns = assertNamespace(str(args, 'namespace', true))
      const labelSelector = str(args, 'labelSelector')
      const res = await core
        .listNamespacedPod({ namespace: ns, ...(labelSelector ? { labelSelector } : {}) })
        .catch((e) => { throw wrapK8sError(e) })
      const pods = (res.items ?? []).map(p => ({
        name: p.metadata?.name,
        phase: p.status?.phase,
        ready: `${(p.status?.containerStatuses ?? []).filter(c => c.ready).length}/${(p.status?.containerStatuses ?? []).length}`,
        restarts: (p.status?.containerStatuses ?? []).reduce((a, c) => a + (c.restartCount ?? 0), 0),
        node: p.spec?.nodeName,
        startTime: p.status?.startTime,
      }))
      return { content: pods }
    },
  },

  getLogs: {
    spec: {
      description: '拉取某 pod 的容器日志(只读)',
      effect: 'read',
      inputSchema: {
        type: 'object',
        required: ['namespace', 'pod'],
        properties: {
          namespace: { type: 'string', description: '目标 namespace(须在允许列表内)' },
          pod: { type: 'string', description: 'pod 名称' },
          container: { type: 'string', description: '容器名(多容器时必填,可选)' },
          tailLines: { type: 'number', description: `尾部行数,上限 ${MAX_TAIL_LINES}(可选)` },
          sinceSeconds: { type: 'number', description: '仅最近 N 秒(可选)' },
          previous: { type: 'boolean', description: '取上一个已终止容器的日志(排查 crash 用,可选)' },
        },
      },
    },
    async call(args) {
      const ns = assertNamespace(str(args, 'namespace', true))
      const pod = str(args, 'pod', true)
      const container = str(args, 'container')
      const sinceSeconds = num(args, 'sinceSeconds')
      let tailLines = num(args, 'tailLines')
      if (tailLines !== undefined) tailLines = Math.min(Math.max(1, Math.floor(tailLines)), MAX_TAIL_LINES)
      const res = await core
        .readNamespacedPodLog({
          name: pod,
          namespace: ns,
          ...(container ? { container } : {}),
          ...(tailLines !== undefined ? { tailLines } : {}),
          ...(sinceSeconds !== undefined ? { sinceSeconds } : {}),
          ...(args?.previous === true ? { previous: true } : {}),
        })
        .catch((e) => { throw wrapK8sError(e) })
      return { content: typeof res === 'string' ? res : (res?.body ?? JSON.stringify(res)) }
    },
  },

  describePod: {
    spec: {
      description: 'pod 的 spec + status 详情(结构化,近似 kubectl describe)',
      effect: 'read',
      inputSchema: {
        type: 'object',
        required: ['namespace', 'pod'],
        properties: {
          namespace: { type: 'string', description: '目标 namespace(须在允许列表内)' },
          pod: { type: 'string', description: 'pod 名称' },
        },
      },
    },
    async call(args) {
      const ns = assertNamespace(str(args, 'namespace', true))
      const pod = str(args, 'pod', true)
      const p = await core
        .readNamespacedPod({ name: pod, namespace: ns })
        .catch((e) => { throw wrapK8sError(e) })
      return {
        content: {
          name: p.metadata?.name,
          namespace: p.metadata?.namespace,
          labels: p.metadata?.labels,
          annotations: p.metadata?.annotations,
          node: p.spec?.nodeName,
          phase: p.status?.phase,
          conditions: p.status?.conditions,
          containers: (p.spec?.containers ?? []).map(c => ({
            name: c.name,
            image: c.image,
            resources: c.resources,
          })),
          containerStatuses: p.status?.containerStatuses,
        },
      }
    },
  },

  getPodStatus: {
    spec: {
      description: 'pod 的精简运行状态(阶段/条件/容器状态)',
      effect: 'read',
      inputSchema: {
        type: 'object',
        required: ['namespace', 'pod'],
        properties: {
          namespace: { type: 'string', description: '目标 namespace(须在允许列表内)' },
          pod: { type: 'string', description: 'pod 名称' },
        },
      },
    },
    async call(args) {
      const ns = assertNamespace(str(args, 'namespace', true))
      const pod = str(args, 'pod', true)
      const p = await core
        .readNamespacedPod({ name: pod, namespace: ns })
        .catch((e) => { throw wrapK8sError(e) })
      return {
        content: {
          phase: p.status?.phase,
          startTime: p.status?.startTime,
          conditions: p.status?.conditions,
          containerStatuses: (p.status?.containerStatuses ?? []).map(c => ({
            name: c.name,
            ready: c.ready,
            restartCount: c.restartCount,
            state: c.state,
            lastState: c.lastState,
          })),
        },
      }
    },
  },

  getEvents: {
    spec: {
      description: '某 namespace(可按 pod 过滤)的事件,排查调度/OOM/拉镜像失败',
      effect: 'read',
      inputSchema: {
        type: 'object',
        required: ['namespace'],
        properties: {
          namespace: { type: 'string', description: '目标 namespace(须在允许列表内)' },
          pod: { type: 'string', description: '仅该 pod 相关事件(可选)' },
        },
      },
    },
    async call(args) {
      const ns = assertNamespace(str(args, 'namespace', true))
      const pod = str(args, 'pod')
      const res = await core
        .listNamespacedEvent({
          namespace: ns,
          ...(pod ? { fieldSelector: `involvedObject.name=${pod}` } : {}),
        })
        .catch((e) => { throw wrapK8sError(e) })
      const events = (res.items ?? []).map(e => ({
        type: e.type,
        reason: e.reason,
        message: e.message,
        object: `${e.involvedObject?.kind}/${e.involvedObject?.name}`,
        count: e.count,
        lastTimestamp: e.lastTimestamp ?? e.eventTime,
      }))
      return { content: events }
    },
  },

  getPodYaml: {
    spec: {
      description: 'pod 的完整 manifest(JSON 形态,含 spec/status 全字段)',
      effect: 'read',
      inputSchema: {
        type: 'object',
        required: ['namespace', 'pod'],
        properties: {
          namespace: { type: 'string', description: '目标 namespace(须在允许列表内)' },
          pod: { type: 'string', description: 'pod 名称' },
        },
      },
    },
    async call(args) {
      const ns = assertNamespace(str(args, 'namespace', true))
      const pod = str(args, 'pod', true)
      const p = await core
        .readNamespacedPod({ name: pod, namespace: ns })
        .catch((e) => { throw wrapK8sError(e) })
      // managedFields 噪声大且无排查价值,剔除。
      if (p.metadata) delete p.metadata.managedFields
      return { content: p }
    },
  },
}

// ── SDK 装配:注册工具节点 + 反向连接 ──────────────────────────
const toolNames = Object.keys(TOOLS)
// 本实例只作为【设备】反向连接到远程网关,不对外提供 HTTP(不调 tb.fetch),
// 故无需 adminSk / bootstrap —— connect() 走的 defaultExpose 只读内存 registrations。
// 远程网关鉴权用的是下面 connect(BASE_URL, SK) 里的 SK,与本地实例引导无关。
const tb = createToolBridge({ state: new MemoryStateStore() })

tb.registerTool(
  'tools/pod-diag',
  {
    List: () => toolNames.map(n => ({ name: n, ...TOOLS[n].spec })),
    Get: (name) => {
      const t = TOOLS[name]
      if (!t) throw TBError.notFound(`unknown tool '${name}'`)
      return { name, ...t.spec }
    },
    Call: (name, args) => {
      const t = TOOLS[name]
      if (!t) throw TBError.notFound(`unknown tool '${name}'`)
      return t.call(args ?? {})
    },
  },
  { description: '集群内只读 K8s 诊断(logs/events/describe/status/list/yaml);无 shell、无 exec' },
)

const conn = tb.connect(BASE_URL, SK, { deviceId: DEVICE_ID })
conn.ready.then(
  mountPath => console.log(`[pod-diag] 已挂载到远程树:${mountPath}(工具:${toolNames.join(', ')})`),
  (err) => {
    console.error(`[pod-diag] 反向连接失败:${err?.message ?? err}`)
    process.exit(1)
  },
)

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.once(sig, () => {
    conn.close()
    process.exit(0)
  })
}
