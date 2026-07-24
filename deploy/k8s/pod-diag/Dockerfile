# tb-pod-diag 镜像:纯 Node 只读诊断服务(@kubernetes/client-node 直连 in-cluster
# APIServer + @tool-bridge/sdk 反向连接网关)。无 kubectl 二进制、无 shell。
#
# 构建(在 deploy/k8s/pod-diag 目录内):
#   docker buildx build --platform linux/amd64 -t <registry>/tb-pod-diag:0.1.0 --push .
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# 可复现构建:锁定 lockfile 版本;--omit=dev 排除冒烟用的 @hono/node-server。
RUN npm ci --omit=dev
COPY src ./src

FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/src ./src
USER node
CMD ["node", "src/index.mjs"]
