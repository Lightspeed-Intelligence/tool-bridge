# tb-pod-diag

集群内**只读**诊断服务:经 `@tool-bridge/sdk` 反向连接到 tool-bridge 网关,把六个结构化只读的 K8s 查询挂到远程树 `device/<deviceId>/tools/pod-diag`。够不到 ACK 集群的 Agent 凭一把 SK + fetch 即可查看 pod 日志、状态、事件。

## 为什么是这个形态(设计决策)

- **不暴露 shell / exec / kubectl**。`kubectl` 二进制放开 = 整个命令面失守;`pods/exec` 在 K8s 层没有"只读"档,进容器即等于可写。二者都被否决。
- **授权面 = namespace-scoped Role**,只给 `pods` / `pods/log` / `events` 的 `get`/`list`。这些子资源在 K8s API 层**没有写动作**,只读是内核保证——即便本 pod 被攻破,SA token 也偷不到写/exec 能力。
- **SA token 只在本 pod 内**,不经 Agent、不经网关。
- 真要 `exec` 进 pod,走人工临时授权,不常设给 Agent。

## 六个只读工具

| 工具 | K8s 调用 | 用途 |
|---|---|---|
| `listPods` | `listNamespacedPod` | 列 pod:阶段/就绪/重启数/节点 |
| `getLogs` | `readNamespacedPodLog` | 拉日志(tailLines/sinceSeconds/container/previous) |
| `describePod` | `readNamespacedPod` | spec + status 详情 |
| `getPodStatus` | `readNamespacedPod` | 精简状态/条件/容器状态 |
| `getEvents` | `listNamespacedEvent` | 事件(调度/OOM/拉镜像失败) |
| `getPodYaml` | `readNamespacedPod` | 完整 manifest(剔 managedFields) |

所有工具的 `namespace` 入参必须落在 `ALLOWED_NAMESPACES` 白名单内。

## 访问方式:纯 HTTP,三入口对等

工具挂上树后就是 HTTP 端点。CLI、Agent、Dashboard 打的是同一个面,没有 CLI 专属通道。
下面 `<gw>` = 网关地址,`<sk>` = **Agent 调用 SK**(见下方"两把 SK")。树路径 `device/pod-diag/tools/pod-diag`(第一段是 deviceId,第二段是注册路径)。

### 发现(GET,自描述)

```sh
# 节点索引:有哪些工具(省略 schema)
curl -H "Authorization: Bearer <sk>" <gw>/device/pod-diag/tools/pod-diag/~help

# 单个工具的完整参数 schema(required + 字段描述都在这一层)
curl -H "Authorization: Bearer <sk>" <gw>/device/pod-diag/tools/pod-diag/getLogs/~help

# 要 JSON(可直接喂 LLM / 渲染表单)
curl -H "Authorization: Bearer <sk>" -H "Accept: application/json" \
  <gw>/device/pod-diag/tools/pod-diag/getLogs/~help
```

### 调用(POST,两种等价形态)

形态 A —— 节点路径 + `{tool, arguments}` 信封:

```sh
curl -X POST <gw>/device/pod-diag/tools/pod-diag \
  -H "Authorization: Bearer <sk>" -H "Content-Type: application/json" \
  -d '{"tool":"getLogs","arguments":{"namespace":"default","pod":"my-pod","tailLines":500,"previous":true}}'
```

形态 B —— 直连工具路径,body 直接就是 arguments:

```sh
curl -X POST <gw>/device/pod-diag/tools/pod-diag/getLogs \
  -H "Authorization: Bearer <sk>" -H "Content-Type: application/json" \
  -d '{"namespace":"default","pod":"my-pod","tailLines":500}'
```

CLI 等价写法(内部就是发上面的 POST):

```sh
tb call device/pod-diag/tools/pod-diag --tool getLogs \
  --args '{"namespace":"default","pod":"my-pod","tailLines":500}'
```

## 两把 SK(别混用)

| 用途 | 谁持有 | scope |
|---|---|---|
| **device SK** | 诊断 pod(`TB_SK` 环境变量,Secret `tb-device-sk`) | 只需 device 注册权 |
| **Agent 调用 SK** | 调用方 Agent | `device/pod-diag/**` 的 `read` + `call` |

权限两级:GET `~help` 要 `read`,POST 调用要 `call`。

## 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `TB_BASE_URL` | ✓ | 网关 base url(https) |
| `TB_SK` | ✓ | device SK |
| `TB_DEVICE_ID` | | 稳定设备 id,缺省 `pod-diag` |
| `ALLOWED_NAMESPACES` | ✓ | 逗号分隔;空 = 拒一切查询 |
| `MAX_TAIL_LINES` | | getLogs 行数上限,缺省 2000 |

## 本地冒烟

`node smoke.mjs` —— 起本地 TB 实例验证反向注册 + HTTP 两种调用形态 + `~help` 两级发现 + SK 鉴权(不连真集群)。构建镜像与部署见上级目录 `../pod-diag.yaml`。

## 已验证 / 未验证

- **已验证**:依赖可解析(`@kubernetes/client-node@1.4.0`、`@tool-bridge/sdk@0.4.0`)、`index.mjs` 语法、K8s client 方法名与 SDK 导出面、`npm ci --omit=dev` 构建、tool-bridge 侧调用链路(冒烟全绿)。
- **未验证**:连真实 in-cluster APIServer 的 K8s 调用(需集群内运行)。首次部署若报错,大概率在 `getLogs`/`listPods` 的返回字段解析处 —— client-node 1.x 返回值直接取(无 `.body`),已按此写。
