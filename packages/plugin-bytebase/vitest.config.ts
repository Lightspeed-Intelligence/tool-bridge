import { cloudflareTest } from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

// 集成测试跑在真实 workerd(与 gateway/plugin-feishu 同基建);Bytebase 换发接口与 MCP
// 上游全部 fetch mock,默认离线确定性。测试配置经 miniflare.bindings 注入。
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          PLUGIN_TOKEN: 'tbp_test_token',
          BYTEBASE_BASE_URL: 'https://bytebase.mock',
          BYTEBASE_ALLOWED_TOOLS: '',
        },
      },
    }),
  ],
})
