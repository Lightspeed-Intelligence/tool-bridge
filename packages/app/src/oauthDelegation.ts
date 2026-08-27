import {
  ACTIONS,
  base64urlEncode,
  KEY_SK_HASH,
  type Scope,
  type SecretKey,
  sha256Hex,
  SKRegistryStore,
  type StateStore,
  TBError,
} from '@tool-bridge/core'
import { z } from 'zod'

export const OAUTH_DELEGATION_AUTHORIZE_PATH = '/oauth/authorize'
export const OAUTH_DELEGATION_TOKEN_PATH = '/oauth/token'
export const OAUTH_DELEGATION_REVOKE_PATH = '/oauth/revoke'

const AUTHORIZATION_CODE_TTL_SECONDS = 90
const AUTHORIZATION_CODE_PREFIX = 'tbc_'
const REFRESH_TOKEN_PREFIX = 'tbr_'
const AUTHORIZATION_CODE_KEY_PREFIX = 'oauth:code:'
const REFRESH_TOKEN_KEY_PREFIX = 'oauth:refresh:'
export const ACCESS_KEY_DESCRIPTION_PREFIX = 'oauth-access:'

const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u
const GRANT_NAME_PATTERN = /^[a-z][a-z0-9_:.]{1,63}$/u

const ScopeSchema = z
  .object({
    pattern: z.string().min(1).max(300),
    actions: z.array(z.enum(ACTIONS)).min(1).max(ACTIONS.length),
    effect: z.enum(['allow', 'deny']).optional(),
  })
  .strict()
  .superRefine((scope, context) => {
    if (
      scope.pattern.startsWith('/')
      || scope.pattern.endsWith('/')
      || scope.pattern.includes('..')
      || scope.pattern === '**'
      || scope.pattern === 'system'
      || scope.pattern.startsWith('system/')
      || scope.pattern === 'device'
      || scope.pattern.startsWith('device/')
    ) {
      context.addIssue({
        code: 'custom',
        message: 'delegated scopes cannot target broad, system, or device paths',
      })
    }
    if (scope.actions.includes('admin') || scope.actions.includes('register')) {
      context.addIssue({
        code: 'custom',
        message: 'delegated scopes cannot include admin or register actions',
      })
    }
  })

const OAuthDelegationGrantSchema = z
  .object({
    name: z.string().regex(GRANT_NAME_PATTERN),
    description: z.string().min(1).max(300),
    scopes: z.array(ScopeSchema).min(1).max(20),
  })
  .strict()

const OAuthDelegationClientSchema = z
  .object({
    clientId: z.string().regex(CLIENT_ID_PATTERN),
    clientSecret: z.string().min(32).max(512),
    redirectUris: z.array(z.string().url().max(2_000)).min(1).max(10),
    grants: z.array(OAuthDelegationGrantSchema).min(1).max(20),
    accessTokenTtlSeconds: z.number().int().min(60).max(3_600).default(900),
    refreshTokenTtlSeconds: z
      .number()
      .int()
      .min(3_600)
      .max(90 * 24 * 3_600)
      .default(30 * 24 * 3_600),
  })
  .strict()
  .superRefine((client, context) => {
    const redirectUris = new Set<string>()
    for (const [index, value] of client.redirectUris.entries()) {
      let url: URL
      try {
        url = new URL(value)
      } catch {
        continue
      }
      const isLoopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost'
      if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
        context.addIssue({
          code: 'custom',
          path: ['redirectUris', index],
          message: 'redirect URI must use HTTPS (HTTP is allowed only for loopback)',
        })
      }
      if (url.username || url.password || url.hash) {
        context.addIssue({
          code: 'custom',
          path: ['redirectUris', index],
          message: 'redirect URI cannot contain credentials or a fragment',
        })
      }
      if (redirectUris.has(value)) {
        context.addIssue({
          code: 'custom',
          path: ['redirectUris', index],
          message: 'redirect URIs must be unique',
        })
      }
      redirectUris.add(value)
    }

    const grantNames = new Set<string>()
    for (const [index, grant] of client.grants.entries()) {
      if (grantNames.has(grant.name)) {
        context.addIssue({
          code: 'custom',
          path: ['grants', index, 'name'],
          message: 'grant names must be unique within a client',
        })
      }
      grantNames.add(grant.name)
    }
  })

const OAuthDelegationClientsSchema = z
  .array(OAuthDelegationClientSchema)
  .max(50)
  .superRefine((clients, context) => {
    const ids = new Set<string>()
    for (const [index, client] of clients.entries()) {
      if (ids.has(client.clientId)) {
        context.addIssue({
          code: 'custom',
          path: [index, 'clientId'],
          message: 'client IDs must be unique',
        })
      }
      ids.add(client.clientId)
    }
  })

export type OAuthDelegationGrant = z.infer<typeof OAuthDelegationGrantSchema>
export type OAuthDelegationClient = z.infer<typeof OAuthDelegationClientSchema>

export class OAuthProtocolError extends Error {
  constructor(
    readonly code:
      | 'invalid_client'
      | 'invalid_grant'
      | 'invalid_request'
      | 'invalid_scope'
      | 'unsupported_grant_type',
    message: string,
  ) {
    super(message)
    this.name = 'OAuthProtocolError'
  }
}

export function parseOAuthDelegationClients(input: unknown): OAuthDelegationClient[] {
  const parsed = OAuthDelegationClientsSchema.safeParse(input)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    const field = issue?.path.join('.') || 'clients'
    throw new Error(`invalid OAuth delegation client configuration at ${field}: ${issue?.message ?? 'invalid value'}`)
  }
  return parsed.data
}

export function parseOAuthDelegationClientsJson(raw: string | undefined): OAuthDelegationClient[] {
  if (raw === undefined || raw.trim() === '') return []
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw new Error('TB_OAUTH_DELEGATION_CLIENTS must be valid JSON')
  }
  return parseOAuthDelegationClients(value)
}

interface AuthorizationCodeRecord {
  clientId: string
  codeChallenge: string
  expiresAt: number
  grantNames: string[]
  nonce: string
  redirectUri: string
  subject: string
  version: 1
}

interface RefreshGrantRecord {
  clientId: string
  expiresAt: number
  grantNames: string[]
  subject: string
  version: 1
}

const AuthorizationCodeRecordSchema = z
  .object({
    version: z.literal(1),
    clientId: z.string().regex(CLIENT_ID_PATTERN),
    redirectUri: z.string().url(),
    subject: z.string().min(1).max(300),
    grantNames: z.array(z.string().regex(GRANT_NAME_PATTERN)).min(1).max(20),
    nonce: z.string().min(20).max(100),
    codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
    expiresAt: z.number().int().positive(),
  })
  .strict()

const RefreshGrantRecordSchema = z
  .object({
    version: z.literal(1),
    clientId: z.string().regex(CLIENT_ID_PATTERN),
    subject: z.string().min(1).max(300),
    grantNames: z.array(z.string().regex(GRANT_NAME_PATTERN)).min(1).max(20),
    expiresAt: z.number().int().positive(),
  })
  .strict()

function randomToken(prefix: string): string {
  return `${prefix}${base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))}`
}

function epochSeconds(nowMs: number): number {
  return Math.floor(nowMs / 1_000)
}

export function delegationClient(
  clients: readonly OAuthDelegationClient[] | undefined,
  clientId: string,
): OAuthDelegationClient | null {
  return clients?.find(client => client.clientId === clientId) ?? null
}

function assertRegisteredGrantNames(
  client: OAuthDelegationClient,
  grantNames: readonly string[],
): void {
  if (grantNames.length === 0 || new Set(grantNames).size !== grantNames.length) {
    throw new OAuthProtocolError('invalid_scope', 'scope must contain unique registered grants')
  }
  const allowed = new Set(client.grants.map(grant => grant.name))
  if (grantNames.some(name => !allowed.has(name))) {
    throw new OAuthProtocolError('invalid_scope', 'one or more requested grants are not allowed')
  }
}

export function assertRegisteredAuthorizationRequest(
  client: OAuthDelegationClient,
  redirectUri: string,
  grantNames: readonly string[],
): void {
  if (!client.redirectUris.includes(redirectUri)) {
    throw new OAuthProtocolError('invalid_request', 'redirect_uri is not registered')
  }
  assertRegisteredGrantNames(client, grantNames)
}

async function authorizationCodeCryptoKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`tb-oauth-delegation-code:${secret}`),
  )
  return await crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
}

async function sealAuthorizationCode(
  record: AuthorizationCodeRecord,
  encryptionKey: string,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    await authorizationCodeCryptoKey(encryptionKey),
    new TextEncoder().encode(JSON.stringify(record)),
  )
  return `${AUTHORIZATION_CODE_PREFIX}${base64urlEncode(iv)}.${base64urlEncode(new Uint8Array(ciphertext))}`
}

export async function createAuthorizationCode(
  encryptionKey: string,
  input: Omit<AuthorizationCodeRecord, 'expiresAt' | 'nonce' | 'version'>,
  nowMs: number,
): Promise<string> {
  const record: AuthorizationCodeRecord = {
    version: 1,
    ...input,
    nonce: base64urlEncode(crypto.getRandomValues(new Uint8Array(24))),
    expiresAt: epochSeconds(nowMs) + AUTHORIZATION_CODE_TTL_SECONDS,
  }
  return await sealAuthorizationCode(record, encryptionKey)
}

function decodeBase64url(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/')
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
  const raw = atob(padded)
  return Uint8Array.from(raw, character => character.charCodeAt(0)) as Uint8Array<ArrayBuffer>
}

async function openAuthorizationCode(
  code: string,
  encryptionKey: string,
): Promise<AuthorizationCodeRecord | null> {
  if (!code.startsWith(AUTHORIZATION_CODE_PREFIX)) return null
  const encoded = code.slice(AUTHORIZATION_CODE_PREFIX.length)
  const separator = encoded.indexOf('.')
  if (separator <= 0) return null
  try {
    const iv = decodeBase64url(encoded.slice(0, separator))
    const ciphertext = decodeBase64url(encoded.slice(separator + 1))
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      await authorizationCodeCryptoKey(encryptionKey),
      ciphertext,
    )
    const parsed = AuthorizationCodeRecordSchema.safeParse(
      JSON.parse(new TextDecoder().decode(plaintext)),
    )
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64urlEncode(new Uint8Array(digest))
}

async function cleanupAuthorizationCodeTombstones(store: StateStore, nowMs: number): Promise<void> {
  const now = epochSeconds(nowMs)
  const page = await store.list(AUTHORIZATION_CODE_KEY_PREFIX, { limit: 20 })
  for (const item of page.items) {
    const value = item.value as { expiresAt?: unknown }
    if (typeof value?.expiresAt === 'number' && value.expiresAt <= now) {
      await store.delete(item.key)
    }
  }
}

export async function consumeAuthorizationCode(
  store: StateStore,
  encryptionKey: string,
  input: {
    clientId: string
    code: string
    codeVerifier: string
    nowMs: number
    redirectUri: string
  },
): Promise<AuthorizationCodeRecord | null> {
  const record = await openAuthorizationCode(input.code, encryptionKey)
  if (record === null) return null
  if (
    record.expiresAt <= epochSeconds(input.nowMs)
    || record.clientId !== input.clientId
    || record.redirectUri !== input.redirectUri
    || record.codeChallenge !== (await pkceChallenge(input.codeVerifier))
  ) {
    return null
  }
  const key = AUTHORIZATION_CODE_KEY_PREFIX + (await sha256Hex(record.nonce))
  if ((await store.get(key)) !== null) return null
  // A tombstone makes redemption one-shot on strong stores and best-effort one-shot on Workers KV.
  // The encrypted code itself remains cross-PoP readable immediately; client auth + PKCE protect
  // the bounded KV propagation window from parties that only observe the browser redirect.
  await store.put(key, { consumedAt: epochSeconds(input.nowMs), expiresAt: record.expiresAt })
  await cleanupAuthorizationCodeTombstones(store, input.nowMs)
  return record
}

async function createRefreshToken(
  store: StateStore,
  input: Omit<RefreshGrantRecord, 'expiresAt' | 'version'>,
  ttlSeconds: number,
  nowMs: number,
): Promise<{ expiresIn: number, token: string }> {
  const token = randomToken(REFRESH_TOKEN_PREFIX)
  const record: RefreshGrantRecord = {
    version: 1,
    ...input,
    expiresAt: epochSeconds(nowMs) + ttlSeconds,
  }
  await store.put(REFRESH_TOKEN_KEY_PREFIX + (await sha256Hex(token)), record)
  return { token, expiresIn: ttlSeconds }
}

export async function readRefreshGrant(
  store: StateStore,
  token: string,
  clientId: string,
  nowMs: number,
): Promise<RefreshGrantRecord | null> {
  if (!token.startsWith(REFRESH_TOKEN_PREFIX)) return null
  const parsed = RefreshGrantRecordSchema.safeParse(
    await store.get(REFRESH_TOKEN_KEY_PREFIX + (await sha256Hex(token))),
  )
  if (!parsed.success) return null
  if (parsed.data.clientId !== clientId || parsed.data.expiresAt <= epochSeconds(nowMs)) return null
  return parsed.data
}

function scopesFor(client: OAuthDelegationClient, grantNames: readonly string[]): Scope[] {
  const selected = new Set(grantNames)
  const scopes = client.grants.flatMap(grant => (selected.has(grant.name) ? grant.scopes : []))
  const unique = new Map<string, Scope>()
  for (const scope of scopes) {
    const key = `${scope.effect ?? 'allow'}\u0000${scope.pattern}\u0000${[...scope.actions].sort().join(',')}`
    unique.set(key, scope)
  }
  return [...unique.values()]
}

export async function issueDelegatedTokens(
  store: StateStore,
  client: OAuthDelegationClient,
  input: { grantNames: string[], issueRefresh: boolean, nowMs: number, subject: string },
): Promise<{
  accessToken: string
  expiresIn: number
  refreshExpiresIn?: number
  refreshToken?: string
}> {
  assertRegisteredGrantNames(client, input.grantNames)
  const now = new Date(input.nowMs).toISOString()
  const expiresAt = new Date(input.nowMs + client.accessTokenTtlSeconds * 1_000).toISOString()
  const sk = new SKRegistryStore(store)
  const { secret } = await sk.write(
    {
      owner: `user:${input.subject}`,
      description: `${ACCESS_KEY_DESCRIPTION_PREFIX}${client.clientId}`,
      scopes: scopesFor(client, input.grantNames),
      expiresAt,
    },
    now,
  )
  if (!input.issueRefresh) {
    return { accessToken: secret, expiresIn: client.accessTokenTtlSeconds }
  }
  const refresh = await createRefreshToken(
    store,
    {
      clientId: client.clientId,
      subject: input.subject,
      grantNames: input.grantNames,
    },
    client.refreshTokenTtlSeconds,
    input.nowMs,
  )
  return {
    accessToken: secret,
    expiresIn: client.accessTokenTtlSeconds,
    refreshToken: refresh.token,
    refreshExpiresIn: refresh.expiresIn,
  }
}

function isDelegatedAccessKey(value: unknown, clientId: string): value is SecretKey {
  if (typeof value !== 'object' || value === null) return false
  const key = value as Partial<SecretKey>
  return (
    typeof key.id === 'string'
    && typeof key.description === 'string'
    && key.description === `${ACCESS_KEY_DESCRIPTION_PREFIX}${clientId}`
  )
}

export async function revokeDelegatedToken(
  store: StateStore,
  clientId: string,
  token: string,
): Promise<void> {
  if (token.startsWith(REFRESH_TOKEN_PREFIX)) {
    const key = REFRESH_TOKEN_KEY_PREFIX + (await sha256Hex(token))
    const parsed = RefreshGrantRecordSchema.safeParse(await store.get(key))
    if (parsed.success && parsed.data.clientId === clientId) await store.delete(key)
    return
  }
  if (!token.startsWith('tbk_')) return
  const hash = await sha256Hex(token)
  const record = await store.get(KEY_SK_HASH + hash)
  if (!isDelegatedAccessKey(record, clientId)) return
  await new SKRegistryStore(store).delete(record.id)
}

async function constantTimeEqual(left: string, right: string): Promise<boolean> {
  const [leftHash, rightHash] = await Promise.all([sha256Hex(left), sha256Hex(right)])
  let difference = leftHash.length ^ rightHash.length
  const size = Math.max(leftHash.length, rightHash.length)
  for (let index = 0; index < size; index += 1) {
    difference |= (leftHash.charCodeAt(index) || 0) ^ (rightHash.charCodeAt(index) || 0)
  }
  return difference === 0
}

export async function authenticateDelegationClient(
  clients: readonly OAuthDelegationClient[] | undefined,
  authorization: string | undefined,
): Promise<OAuthDelegationClient | null> {
  if (!authorization?.startsWith('Basic ')) return null
  let decoded: string
  try {
    decoded = atob(authorization.slice('Basic '.length).trim())
  } catch {
    return null
  }
  const separator = decoded.indexOf(':')
  if (separator <= 0) return null
  const clientId = decoded.slice(0, separator)
  const secret = decoded.slice(separator + 1)
  const client = delegationClient(clients, clientId)
  if (client === null || !(await constantTimeEqual(secret, client.clientSecret))) return null
  return client
}

export function assertRefreshScope(
  approved: readonly string[],
  requested: readonly string[],
): string[] {
  const selected = requested.length > 0 ? [...new Set(requested)] : [...approved]
  const allowed = new Set(approved)
  if (selected.length === 0 || selected.some(name => !allowed.has(name))) {
    throw new OAuthProtocolError('invalid_scope', 'requested scope exceeds the user-approved grant')
  }
  return selected
}

export function requireOAuthConfiguration(
  encryptionKey: string | undefined,
  feishuLoginSecretRef: string | undefined,
): asserts encryptionKey is string {
  if (encryptionKey === undefined || feishuLoginSecretRef === undefined) {
    throw new TBError('unavailable', 'OAuth delegation is not configured', { retryable: false })
  }
}

/**
 * 清掉某人授予某 client 的全部 refresh token。
 *
 * 给 `system/my-keys` 的自助撤销用:用户在页面撤销一个委托 access key 时,若不同时清掉
 * refresh token,第三方应用可用它换一把新 access key —— 撤销被绕过。官方 revoke 端点
 * (revokeDelegatedToken)对单个 token 两者都清;这里按 (clientId, subject) 扫全量清。
 *
 * @param description 被撤销 key 的原始 description(`oauth-access:<clientId>`)。
 */
export async function revokeDelegationGrantsFor(
  store: StateStore,
  owner: string,
  description: string,
): Promise<void> {
  if (!description.startsWith(ACCESS_KEY_DESCRIPTION_PREFIX)) return
  const clientId = description.slice(ACCESS_KEY_DESCRIPTION_PREFIX.length).trim()
  if (clientId === '') return

  let cursor: string | undefined
  do {
    const page = await store.list(
      REFRESH_TOKEN_KEY_PREFIX,
      cursor !== undefined ? { limit: 200, cursor } : { limit: 200 },
    )
    for (const item of page.items) {
      const parsed = RefreshGrantRecordSchema.safeParse(item.value)
      // subject 即 owner;两者都匹配才删,避免误删他人或其他 client 的授权。
      if (!parsed.success) continue
      if (parsed.data.clientId !== clientId || parsed.data.subject !== owner) continue
      await store.delete(item.key)
    }
    cursor = page.cursor
  } while (cursor !== undefined)
}
