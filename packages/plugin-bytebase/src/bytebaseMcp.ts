/**
 * Bytebase 自托管 MCP(`{baseUrl}/mcp`)的 Streamable HTTP client 封装。
 *
 * - 认证:标准 `Authorization: Bearer <token>`(SA 访问令牌,见 token.ts)。上游
 *   authMiddleware 校验 JWT 签名 + audience(`bb.user.access` / `bb.oauth2.access`),
 *   失效一律 401 并带 RFC 9728 WWW-Authenticate。
 * - 会话:上游签发的 Mcp-Session-Id 缓存在 isolate 内存;失效信号(400/404)→ 清缓存
 *   完整重握手一次(实测:有效 token + 陈旧 sessionId → 404)。凭证过期(401)由调用方
 *   (index.ts)强制重换发 token 后重试。
 * - 会话键控 `<baseUrl>|<email>`:同一部署服务多实例/多账号挂载,会话不得串号。
 * - workerd 禁 eval,JSON Schema 校验用 SDK 自带的 @cfworker/json-schema 解释执行实现
 *   (同 gateway providers/mcp.ts 与 plugin-feishu 的坑)。
 */

import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/cfworker'
import { isTBError, normalizeUpstreamError } from '@tool-bridge/core'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'

export const MCP_PATH = '/mcp'

/** 上游工具形状(仅取转发所需字段;与 gateway providers/mcp.ts 同构)。 */
export interface BytebaseTool {
  annotations?: { destructiveHint?: boolean, readOnlyHint?: boolean }
  description?: string
  inputSchema?: unknown
  name: string
}

export interface BytebaseToolResult {
  content?: unknown
  isError?: boolean
}

interface CachedSession {
  protocolVersion?: string
  sessionId: string
}

const sessions = new Map<string, CachedSession>()

/** 测试用:清空进程内 MCP 会话缓存。 */
export function clearSessionCache(): void {
  sessions.clear()
}

export interface BytebaseMcpConfig {
  /** 会话缓存键(`<baseUrl>|<email>`,由 index.ts 拼)。 */
  sessionKey: string
  token: string
  url: string
}

/** SDK 在 initialize 后自动 GET 打开可选 standalone SSE;这里不消费,直接 405。 */
const noStandaloneSseFetch: typeof fetch = (input, init) => {
  const method = init?.method ?? (input instanceof Request ? input.method : 'GET')
  if (String(method).toUpperCase() === 'GET') {
    return Promise.resolve(new Response(null, { status: 405, statusText: 'Method Not Allowed' }))
  }
  return fetch(input, init)
}

function isSessionInvalid(err: unknown): boolean {
  return err instanceof StreamableHTTPError && (err.code === 404 || err.code === 400)
}

/** 上游 401:访问令牌过期/无效,调用方应强制重换发后重试。 */
export function isUnauthorized(err: unknown): boolean {
  return err instanceof StreamableHTTPError && err.code === 401
}

async function withSession<T>(
  cfg: BytebaseMcpConfig,
  fn: (client: Client) => Promise<T>,
): Promise<T> {
  const makeTransport = (sessionId: string | undefined): StreamableHTTPClientTransport =>
    new StreamableHTTPClientTransport(new URL(cfg.url), {
      fetch: noStandaloneSseFetch,
      requestInit: { headers: { Authorization: `Bearer ${cfg.token}` } },
      ...(sessionId !== undefined ? { sessionId } : {}),
    })
  const makeClient = (): Client =>
    new Client(
      { name: 'tb-plugin-bytebase', version: '0.1.0' },
      { jsonSchemaValidator: new CfWorkerJsonSchemaValidator() },
    )

  const runFresh = async (): Promise<T> => {
    const transport = makeTransport(undefined)
    const client = makeClient()
    await client.connect(transport)
    if (transport.sessionId !== undefined) {
      sessions.set(cfg.sessionKey, {
        sessionId: transport.sessionId,
        ...(transport.protocolVersion !== undefined
          ? { protocolVersion: transport.protocolVersion }
          : {}),
      })
    } else {
      sessions.delete(cfg.sessionKey)
    }
    return await fn(client)
  }

  const session = sessions.get(cfg.sessionKey)
  if (session !== undefined) {
    const transport = makeTransport(session.sessionId)
    const client = makeClient()
    await client.connect(transport) // sessionId 已设 → SDK 跳过 initialize
    if (session.protocolVersion !== undefined) {
      transport.setProtocolVersion(session.protocolVersion)
    }
    try {
      return await fn(client)
    } catch (err) {
      if (!isSessionInvalid(err)) throw err
      sessions.delete(cfg.sessionKey)
      // 落回完整握手重试一次
    }
  }
  return await runFresh()
}

/** 传输/协议错误归一 TBError;401 原样抛给调用方做 token 重换发。 */
async function guard<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (err) {
    if (isTBError(err) || isUnauthorized(err)) throw err
    if (err instanceof StreamableHTTPError && err.code !== undefined) {
      throw normalizeUpstreamError({ kind: 'http', status: err.code, message: err.message })
    }
    throw normalizeUpstreamError({
      kind: 'network',
      message: err instanceof Error ? err.message : String(err),
    })
  }
}

export async function listTools(cfg: BytebaseMcpConfig): Promise<BytebaseTool[]> {
  return guard(async () => {
    const res = (await withSession(cfg, c => c.listTools())) as { tools: BytebaseTool[] }
    return res.tools
  })
}

export async function callTool(
  cfg: BytebaseMcpConfig,
  name: string,
  args: Record<string, unknown>,
): Promise<BytebaseToolResult> {
  return guard(async () => {
    const res = await withSession(cfg, c => c.callTool({ name, arguments: args }))
    return res as BytebaseToolResult
  })
}
