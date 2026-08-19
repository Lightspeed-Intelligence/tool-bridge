import { isTBError } from '@tool-bridge/core'
import type { AppContext, TbHono } from '../deps'
import type { RouteEnv } from './env'
import {
  assertRefreshScope,
  assertRegisteredAuthorizationRequest,
  authenticateDelegationClient,
  consumeAuthorizationCode,
  delegationClient,
  issueDelegatedTokens,
  OAUTH_DELEGATION_AUTHORIZE_PATH,
  OAUTH_DELEGATION_REVOKE_PATH,
  OAUTH_DELEGATION_TOKEN_PATH,
  OAuthProtocolError,
  readRefreshGrant,
  requireOAuthConfiguration,
  revokeDelegatedToken,
} from '../oauthDelegation'
import {
  buildAuthorizeUrl,
  FEISHU_CALLBACK_PATH,
  newDelegationLoginState,
  parseFeishuCredential,
} from '../feishuLogin'

const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/u
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/u

function oauthHeaders(): Record<string, string> {
  return {
    'cache-control': 'private, no-store',
    'pragma': 'no-cache',
    'content-type': 'application/json; charset=utf-8',
  }
}

function oauthError(
  error: string,
  description: string,
  status: 400 | 401 | 500 = 400,
): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: oauthHeaders(),
  })
}

function protocolError(error: unknown): Response {
  if (error instanceof OAuthProtocolError) {
    return oauthError(error.code, error.message, error.code === 'invalid_client' ? 401 : 400)
  }
  if (isTBError(error) && error.code === 'unavailable') {
    return oauthError('temporarily_unavailable', 'OAuth delegation is unavailable', 500)
  }
  return oauthError('server_error', 'OAuth delegation failed', 500)
}

function parseGrantNames(scope: string | undefined): string[] {
  if (scope === undefined) return []
  return scope
    .trim()
    .split(/\s+/u)
    .filter(Boolean)
}

function required(params: URLSearchParams, name: string): string {
  const value = params.get(name)
  if (value === null || value === '') {
    throw new OAuthProtocolError('invalid_request', `${name} is required`)
  }
  return value
}

async function formParams(context: AppContext): Promise<URLSearchParams> {
  const contentType = context.req.header('content-type')?.toLowerCase() ?? ''
  if (!contentType.startsWith('application/x-www-form-urlencoded')) {
    throw new OAuthProtocolError(
      'invalid_request',
      'content-type must be application/x-www-form-urlencoded',
    )
  }
  return new URLSearchParams(await context.req.text())
}

function loginRedirectUri(context: AppContext, env: RouteEnv): string {
  return `${env.deps.canonicalOrigin ?? new URL(context.req.url).origin}${FEISHU_CALLBACK_PATH}`
}

export function registerOAuthDelegationRoutes(app: TbHono, env: RouteEnv): void {
  const { deps } = env

  app.get(OAUTH_DELEGATION_AUTHORIZE_PATH, async (context) => {
    try {
      requireOAuthConfiguration(deps.encryptionKey, deps.feishuLoginSecretRef)
      const url = new URL(context.req.url)
      const responseType = required(url.searchParams, 'response_type')
      if (responseType !== 'code') {
        throw new OAuthProtocolError('invalid_request', 'response_type must be code')
      }
      const clientId = required(url.searchParams, 'client_id')
      const client = delegationClient(deps.oauthDelegationClients, clientId)
      if (client === null) throw new OAuthProtocolError('invalid_request', 'unknown client_id')
      const redirectUri = required(url.searchParams, 'redirect_uri')
      const grantNames = parseGrantNames(required(url.searchParams, 'scope'))
      assertRegisteredAuthorizationRequest(client, redirectUri, grantNames)
      const clientState = required(url.searchParams, 'state')
      if (clientState.length < 16 || clientState.length > 512) {
        throw new OAuthProtocolError('invalid_request', 'state must contain 16 to 512 characters')
      }
      const codeChallengeMethod = required(url.searchParams, 'code_challenge_method')
      const codeChallenge = required(url.searchParams, 'code_challenge')
      if (codeChallengeMethod !== 'S256' || !PKCE_CHALLENGE_PATTERN.test(codeChallenge)) {
        throw new OAuthProtocolError('invalid_request', 'PKCE S256 code challenge is required')
      }

      await deps.ensureReady?.()
      const secretRef = deps.feishuLoginSecretRef
      if (secretRef === undefined) {
        throw new OAuthProtocolError('invalid_request', 'Feishu identity provider is unavailable')
      }
      const credential = parseFeishuCredential(await deps.secrets.resolve(secretRef), secretRef)
      const state = await newDelegationLoginState(
        deps.encryptionKey,
        Date.now(),
        {
          clientId,
          clientState,
          codeChallenge,
          grantNames,
          redirectUri,
        },
      )
      return context.redirect(
        buildAuthorizeUrl(credential.app_id, loginRedirectUri(context, env), state),
        302,
      )
    } catch (error) {
      return protocolError(error)
    }
  })

  app.post(OAUTH_DELEGATION_TOKEN_PATH, async (context) => {
    try {
      const client = await authenticateDelegationClient(
        deps.oauthDelegationClients,
        context.req.header('authorization'),
      )
      if (client === null) throw new OAuthProtocolError('invalid_client', 'client authentication failed')
      const params = await formParams(context)
      const grantType = required(params, 'grant_type')

      if (grantType === 'authorization_code') {
        const codeVerifier = required(params, 'code_verifier')
        if (!PKCE_VERIFIER_PATTERN.test(codeVerifier)) {
          throw new OAuthProtocolError('invalid_grant', 'authorization code is invalid or expired')
        }
        const encryptionKey = deps.encryptionKey
        if (encryptionKey === undefined) {
          throw new OAuthProtocolError('invalid_grant', 'authorization code is invalid or expired')
        }
        const record = await consumeAuthorizationCode(deps.state, encryptionKey, {
          clientId: client.clientId,
          code: required(params, 'code'),
          codeVerifier,
          redirectUri: required(params, 'redirect_uri'),
          nowMs: Date.now(),
        })
        if (record === null) {
          throw new OAuthProtocolError('invalid_grant', 'authorization code is invalid or expired')
        }
        const issued = await issueDelegatedTokens(deps.state, client, {
          subject: record.subject,
          grantNames: record.grantNames,
          issueRefresh: true,
          nowMs: Date.now(),
        })
        return new Response(
          JSON.stringify({
            access_token: issued.accessToken,
            token_type: 'Bearer',
            expires_in: issued.expiresIn,
            refresh_token: issued.refreshToken,
            refresh_expires_in: issued.refreshExpiresIn,
            scope: record.grantNames.join(' '),
            subject: record.subject,
          }),
          { headers: oauthHeaders() },
        )
      }

      if (grantType === 'refresh_token') {
        const refreshToken = required(params, 'refresh_token')
        const record = await readRefreshGrant(
          deps.state,
          refreshToken,
          client.clientId,
          Date.now(),
        )
        if (record === null) {
          throw new OAuthProtocolError('invalid_grant', 'refresh token is invalid or expired')
        }
        const grantNames = assertRefreshScope(
          record.grantNames,
          parseGrantNames(params.get('scope') ?? undefined),
        )
        const issued = await issueDelegatedTokens(deps.state, client, {
          subject: record.subject,
          grantNames,
          issueRefresh: false,
          nowMs: Date.now(),
        })
        return new Response(
          JSON.stringify({
            access_token: issued.accessToken,
            token_type: 'Bearer',
            expires_in: issued.expiresIn,
            scope: grantNames.join(' '),
            subject: record.subject,
          }),
          { headers: oauthHeaders() },
        )
      }

      throw new OAuthProtocolError('unsupported_grant_type', 'grant_type is not supported')
    } catch (error) {
      return protocolError(error)
    }
  })

  app.post(OAUTH_DELEGATION_REVOKE_PATH, async (context) => {
    try {
      const client = await authenticateDelegationClient(
        deps.oauthDelegationClients,
        context.req.header('authorization'),
      )
      if (client === null) throw new OAuthProtocolError('invalid_client', 'client authentication failed')
      const params = await formParams(context)
      await revokeDelegatedToken(deps.state, client.clientId, required(params, 'token'))
      return new Response(null, { status: 200, headers: oauthHeaders() })
    } catch (error) {
      return protocolError(error)
    }
  })
}
