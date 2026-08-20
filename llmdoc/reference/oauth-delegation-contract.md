# OAuth 用户委托契约

Tool Bridge 可以让预注册的机密客户端（例如 TCode）代表一名已通过飞书认证的用户，获取
短期、最小权限的 SK。它与 Dashboard 的 `/login` 相互独立：前者返回 OAuth Token，后者仍只
给交互式用户自己的登录 SK。

## 协议

1. 客户端生成随机 `state` 与 PKCE verifier/challenge。
2. 浏览器访问 `GET /oauth/authorize`，参数为标准的 `response_type=code`、`client_id`、
   `redirect_uri`、空格分隔的命名 `scope`、`state`、`code_challenge_method=S256` 和
   `code_challenge`。
3. Tool Bridge 严格校验客户端、完整 redirect URI 与命名 grant，然后跳转飞书登录。
4. 飞书回调确认用户 `open_id` 后，只向已注册 redirect URI 返回短时加密授权码和原 `state`。
5. 客户端以 HTTP Basic 认证调用 `POST /oauth/token`：
   - `grant_type=authorization_code` 同时提交 `code`、原 `redirect_uri` 与 `code_verifier`；
   - 成功返回 `access_token`、`refresh_token`、`expires_in`、`refresh_expires_in`、`scope`，
     以及扩展字段 `subject`（真实飞书 `open_id`，供客户端绑定发起人）。
   - `grant_type=refresh_token` 可把 `scope` 收窄为用户已批准 grant 的子集，不能扩大。
6. `POST /oauth/revoke` 使用同一客户端认证并提交 `token`；访问 SK 立即禁用，刷新授权删除。
   未知 token 也返回 200，避免形成枚举接口。

Token 与错误响应均带 `Cache-Control: private, no-store`。OAuth 错误统一为
`{error,error_description}`；HTBP 其余接口仍使用原 `{code,message,retryable}`，两套错误形状不
混用。

## 配置

`TB_OAUTH_DELEGATION_CLIENTS` 是 JSON 数组，必须作为部署 secret 注入。每个客户端包含：

```json
{
  "clientId": "tcode",
  "clientSecret": "至少 32 字符的随机值",
  "redirectUris": [
    "https://tcode.example.com/api/v1/integrations/tool-bridge/callback"
  ],
  "accessTokenTtlSeconds": 900,
  "refreshTokenTtlSeconds": 2592000,
  "grants": [
    {
      "name": "database_production_read",
      "description": "Read production diagnostics",
      "scopes": [
        { "pattern": "plugins/bytebase", "actions": ["read", "call"] },
        { "pattern": "plugins/bytebase/**", "actions": ["read", "call"] }
      ]
    }
  ]
}
```

还必须配置 `TB_SECRET_ENCRYPTION_KEY`、`TB_FEISHU_LOGIN_SECRET_REF`、规范 HTTPS
`TB_CANONICAL_ORIGIN`，并在 SecretStore 的引用名下保存飞书 `{app_id,app_secret}`。飞书应用
回调固定为 `<TB_CANONICAL_ORIGIN>/~feishu/callback`。

Workers 用 `wrangler secret put TB_OAUTH_DELEGATION_CLIENTS`，Node/Docker 以 secret env 注入。
SDK 嵌入方传等价的 `oauthDelegationClients` 结构。

## 安全边界

- redirect URI 完整字符串匹配，不接受前缀、通配或请求期任意回跳。
- 授权码同时绑定客户端、redirect URI、PKCE challenge、用户和命名 grant；密文可跨 Workers
  PoP 立即兑换，不依赖 KV 写传播。
- 强一致 StateStore 对授权码提供严格单次消费；Workers KV 的消费墓碑存在最终一致窗口，因此
  机密客户端认证与 PKCE 仍是必须的第二、第三道边界。窗口内重复兑换最多得到同一用户已明确
  批准范围内的额外短期 SK，不能扩大权限。
- delegation 配置拒绝 `**`、`system/**`、`device/**`、`admin` 与 `register`；客户端只能从部署者
  预注册的命名 grant 中选择。
- access token 是已有 SK 模型，明文只在签发响应中出现；Refresh Token 只存 hash，日志、URL、
  Dashboard、调用历史与管理响应都不得记录 token 或客户端 secret。
- 客户端必须比较 Token 响应中的 `subject` 与自己发起授权时绑定的真实用户，防止群内其他成员
  使用共享卡片链接替代发起人授权。

该流程属于浏览器/服务到服务认证协议，不是 HTBP 管理资源，因此没有对应的 `tb` 子命令或
Dashboard 管理旁路。客户端注册仍由部署配置控制，避免运行期公开增加 OAuth 客户端。
