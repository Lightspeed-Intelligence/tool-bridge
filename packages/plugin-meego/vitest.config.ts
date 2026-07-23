import { cloudflareTest } from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

// 集成测试跑在真实 workerd(与 gateway/plugin-feishu 同基建);Meego open_api 全部
// fetch mock,默认离线确定性。测试凭证经 miniflare.bindings 注入。
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          PLUGIN_TOKEN: 'tbp_test_token',
          MEEGO_BASE_URL: 'https://meego-api.mock',
        },
      },
    }),
  ],
})
