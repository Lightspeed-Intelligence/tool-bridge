import {
  ArrowRight,
  Boxes,
  ChevronDown,
  KeyRound,
  Loader2,
  LogIn,
  Moon,
  Network,
  ShieldCheck,
  Sun,
  X,
} from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import {
  type ApiError,
  consumeFeishuLogin,
  getFeishuLoginStatus,
  validateConnection,
} from '@/lib/api'
import { useSession } from '@/lib/session-context'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTheme } from '@/lib/theme'
import hero from '@/assets/hero.png'

const FEATURES = [
  { icon: Network, label: '渐进发现', text: '从 /~help 开始，按需展开能力树' },
  { icon: Boxes, label: '统一调用', text: '工具、Context 与设备共用入口' },
  { icon: ShieldCheck, label: '身份签发', text: '飞书登录后自动获得最小权限凭据' },
] as const

function clearFeishuLoginMarker(): void {
  const url = new URL(window.location.href)
  url.searchParams.delete('login')
  window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)
}

function endpointLabel(baseUrl: string): string {
  if (baseUrl.trim() === '') return `同源 · ${window.location.host}`
  try {
    return new URL(baseUrl).host || baseUrl
  } catch {
    return baseUrl
  }
}

function connectionErrorMessage(error: ApiError | null): string {
  if (!error) return ''
  if (error.status === 401) return 'Secret Key 无法识别：它可能无效、已禁用或已过期。'
  if (error.status === 403) return '凭据已识别，但没有读取根节点 /~help 的权限。'
  if (error.code === 'network') {
    return '浏览器无法到达该网关。请检查地址和网络；跨域连接还需由网关允许 CORS。'
  }
  return error.message
}

/**
 * 登录门：GET /~help 通过即建立本地 profile。优先恢复已保存档案，
 * 同时保留同源与跨域 BaseURL 两种新连接方式。
 */
export function LoginPage() {
  const { login, profiles, switchTo, removeProfile } = useSession()
  const [theme, toggleTheme] = useTheme()
  const [baseUrl, setBaseUrl] = useState('')
  const [sk, setSk] = useState('')
  const [name, setName] = useState('default')
  const [manualOpen, setManualOpen] = useState(false)
  const [handoffPending, setHandoffPending] = useState(false)
  const [feishuError, setFeishuError] = useState('')
  const handoffAttempted = useRef(false)

  const feishuStatus = useQuery({
    queryKey: ['public', 'feishu-login-status'],
    queryFn: getFeishuLoginStatus,
    retry: false,
    staleTime: 60_000,
  })

  const mutation = useMutation({
    mutationFn: async () => {
      const normalized = baseUrl.trim().replace(/\/+$/, '')
      await validateConnection({ baseUrl: normalized, sk: sk.trim() })
      return { name: name.trim() || 'default', baseUrl: normalized, sk: sk.trim() }
    },
    onSuccess: profile => login(profile),
  })

  const error = mutation.error as ApiError | null
  const usesSameOrigin = baseUrl.trim() === ''
  const target = usesSameOrigin ? window.location.origin : baseUrl.trim()
  const feishuEnabled = feishuStatus.data?.enabled === true
  const showManual = manualOpen || (!feishuStatus.isPending && !feishuEnabled)

  useEffect(() => {
    if (
      new URLSearchParams(window.location.search).get('login') !== 'feishu'
        || handoffAttempted.current
    ) return
    handoffAttempted.current = true
    setHandoffPending(true)
    void (async () => {
      try {
        const handoff = await consumeFeishuLogin()
        const handoffOrigin = new URL(handoff.baseUrl).origin
        const profileBaseUrl = handoffOrigin === window.location.origin ? '' : handoffOrigin
        await validateConnection({ baseUrl: profileBaseUrl, sk: handoff.sk })
        clearFeishuLoginMarker()
        login({ name: handoff.profile || 'feishu', baseUrl: profileBaseUrl, sk: handoff.sk })
      } catch (caught) {
        clearFeishuLoginMarker()
        setFeishuError(
          caught instanceof Error ? caught.message : '飞书登录接入失败，请重新尝试',
        )
      } finally {
        setHandoffPending(false)
      }
    })()
  }, [login])

  return (
    <div className="relative h-svh overflow-x-hidden overflow-y-auto bg-background">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.16] [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:48px_48px]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -top-56 left-[18%] h-[34rem] w-[34rem] rounded-full bg-primary/[0.07] blur-3xl"
      />

      <header className="relative z-10 flex h-16 items-center justify-between px-5 sm:px-8 lg:px-12">
        <div className="flex items-center gap-3">
          <img alt="" className="size-7 dark:invert" src="/ui/icon-light.png" />
          <span className="font-mono text-sm tracking-tight">
            tool
            <span className="text-primary">-</span>
            bridge
          </span>
          <span className="hidden rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider text-muted-foreground sm:inline">
            HTBP CONTROL PLANE
          </span>
        </div>
        <Button aria-label="切换主题" onClick={toggleTheme} size="icon-sm" variant="ghost">
          {theme === 'dark' ? <Sun /> : <Moon />}
        </Button>
      </header>

      <main className="relative z-10 mx-auto grid min-h-[calc(100svh-4rem)] w-full max-w-7xl items-center gap-12 px-5 py-8 sm:px-8 lg:grid-cols-[minmax(0,1.08fr)_minmax(22rem,0.72fr)] lg:px-12 lg:py-12">
        <section aria-labelledby="login-product-title" className="hidden min-w-0 lg:block">
          <p className="text-xs font-semibold tracking-[0.2em] text-primary uppercase">
            One tree. One gateway.
          </p>
          <h1
            className="mt-4 max-w-2xl text-4xl leading-[1.08] font-semibold tracking-[-0.04em] xl:text-5xl"
            id="login-product-title"
          >
            让每一个 Agent，
            <span className="text-muted-foreground">都能安全地找到并使用组织能力。</span>
          </h1>
          <p className="mt-5 max-w-xl text-base leading-7 text-muted-foreground">
            使用企业飞书身份进入自描述的 HTBP 树，网关自动签发最小权限凭据，
            在同一控制面管理工具、上下文、设备与联邦服务。
          </p>

          <div className="mt-9 grid max-w-2xl grid-cols-3 gap-6">
            {FEATURES.map(({ icon: Icon, label, text }) => (
              <div className="border-l border-border/80 pl-4" key={label}>
                <Icon className="size-4 text-primary" />
                <p className="mt-3 text-sm font-medium">{label}</p>
                <p className="mt-1.5 text-xs leading-5 text-muted-foreground">{text}</p>
              </div>
            ))}
          </div>

          <div aria-hidden className="absolute bottom-5 left-[42%] opacity-45 xl:bottom-3">
            <img alt="" className="w-40 xl:w-48" src={hero} />
          </div>
        </section>

        <section aria-labelledby="login-title" className="mx-auto w-full max-w-md">
          <div className="relative overflow-hidden rounded-xl border bg-card/80 p-5 shadow-xl shadow-black/[0.08] backdrop-blur-xl sm:p-7">
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent" />

            <div className="mb-6">
              <div className="mb-4 grid size-10 place-items-center rounded-lg border bg-primary/[0.07] text-primary">
                <LogIn className="size-4.5" />
              </div>
              <h2 className="text-xl font-semibold tracking-[-0.02em]" id="login-title">
                登录 Tool Bridge
              </h2>
              <p className="mt-1.5 text-sm leading-6 text-muted-foreground">
                使用飞书企业身份登录，或恢复已有的本地连接档案。
              </p>
            </div>

            {profiles.length > 0 && (
              <section aria-labelledby="saved-profile-title" className="mb-6">
                <div className="mb-2.5 flex items-center justify-between gap-3">
                  <h3 className="text-xs font-medium" id="saved-profile-title">
                    继续使用
                  </h3>
                  <span className="rounded-full bg-secondary px-2 py-0.5 font-mono text-[10px] text-muted-foreground">
                    {profiles.length}
                    {' '}
                    个本地档案
                  </span>
                </div>
                <div className="grid max-h-52 gap-2 overflow-y-auto pr-1">
                  {profiles.map(profile => (
                    <div
                      className="group/profile flex min-w-0 overflow-hidden rounded-md border bg-background/45"
                      key={profile.id}
                    >
                      <button
                        className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2.5 text-left outline-none transition-colors hover:bg-secondary/45 focus-visible:bg-secondary focus-visible:ring-2 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50"
                        disabled={mutation.isPending}
                        onClick={() => switchTo(profile.name)}
                        title={`使用 ${profile.name} · ${profile.baseUrl || window.location.origin}`}
                        type="button"
                      >
                        <span className="grid size-8 shrink-0 place-items-center rounded-md border bg-card text-muted-foreground">
                          <KeyRound className="size-3.5" />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-mono text-xs text-foreground">
                            {profile.name}
                          </span>
                          <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">
                            {endpointLabel(profile.baseUrl)}
                          </span>
                        </span>
                        <ArrowRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-hover/profile:translate-x-0.5 group-hover/profile:text-primary" />
                      </button>
                      <Button
                        aria-label={`删除档案 ${profile.name}`}
                        className="h-auto w-10 rounded-none border-l text-muted-foreground hover:text-destructive"
                        disabled={mutation.isPending}
                        onClick={() => removeProfile(profile.name)}
                        size="icon"
                        title="删除本地档案"
                        type="button"
                        variant="ghost"
                      >
                        <X className="size-3.5" />
                      </Button>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section
              aria-labelledby="enterprise-login-title"
              className={profiles.length > 0 ? 'border-t pt-5' : undefined}
            >
              <div className="mb-4 flex items-center justify-between gap-3">
                <h3 className="text-xs font-medium" id="enterprise-login-title">
                  企业账号
                </h3>
                <span className="font-mono text-[10px] text-muted-foreground">FEISHU OAUTH</span>
              </div>

              {feishuStatus.isPending
                ? (
                    <div className="flex items-center gap-2 rounded-md border bg-background/45 px-3 py-3 text-xs text-muted-foreground">
                      <Loader2 className="size-3.5 animate-spin text-primary" />
                      正在检查企业登录能力…
                    </div>
                  )
                : feishuEnabled
                  ? handoffPending
                    ? (
                        <Button className="w-full" disabled size="lg">
                          <Loader2 className="animate-spin" />
                          正在接入控制台…
                        </Button>
                      )
                    : (
                        <Button asChild className="w-full" size="lg">
                          <a href="/login?continue=%2Fui%2F">
                            <LogIn />
                            使用飞书登录
                            <ArrowRight className="ml-auto" />
                          </a>
                        </Button>
                      )
                  : (
                      <div className="rounded-md border bg-background/45 px-3 py-3 text-xs leading-5 text-muted-foreground">
                        当前网关未启用飞书登录，请使用已有 Secret Key 接入。
                      </div>
                    )}

              {feishuEnabled && (
                <p className="mt-3 text-[11px] leading-5 text-muted-foreground">
                  飞书 token 仅用于服务端确认企业身份；控制台接收网关签发的 Tool Bridge
                  Secret Key，并只保存在当前浏览器。
                </p>
              )}

              {feishuError && (
                <div
                  className="mt-3 rounded-md border border-destructive/40 bg-destructive/[0.07] px-3 py-2.5 text-xs leading-5 text-destructive"
                  role="alert"
                >
                  {feishuError}
                </div>
              )}
            </section>

            {feishuEnabled && (
              <Button
                aria-expanded={manualOpen}
                className="mt-3 w-full justify-between text-muted-foreground"
                onClick={() => setManualOpen(open => !open)}
                type="button"
                variant="ghost"
              >
                已有 Secret Key / 连接其它网关
                <ChevronDown
                  className={`transition-transform ${manualOpen ? 'rotate-180' : ''}`}
                />
              </Button>
            )}

            {showManual && (
              <section aria-labelledby="manual-connection-title" className="mt-5 border-t pt-5">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <h3 className="text-xs font-medium" id="manual-connection-title">
                    手工连接
                  </h3>
                  <span className="font-mono text-[10px] text-muted-foreground">GET /~help</span>
                </div>

                <form
                  className="grid gap-4"
                  onSubmit={(event) => {
                    event.preventDefault()
                    if (!mutation.isPending) mutation.mutate()
                  }}
                >
                  <div className="grid gap-2">
                    <Label>连接目标</Label>
                    <div className="flex min-w-0 items-center gap-3 rounded-md border bg-background/45 p-3">
                      <span className="grid size-8 shrink-0 place-items-center rounded-md bg-secondary text-primary">
                        <Network className="size-3.5" />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs font-medium">当前网关</span>
                        <span className="mt-0.5 block truncate font-mono text-[10px] text-muted-foreground">
                          {window.location.origin}
                        </span>
                      </span>
                      <Button
                        disabled={mutation.isPending}
                        onClick={() => {
                          setBaseUrl('')
                          if (!mutation.isPending) mutation.reset()
                        }}
                        size="xs"
                        type="button"
                        variant={usesSameOrigin ? 'secondary' : 'outline'}
                      >
                        {usesSameOrigin ? <ShieldCheck /> : <ArrowRight />}
                        {usesSameOrigin ? '已选择' : '改用同源'}
                      </Button>
                    </div>
                  </div>

                  <div className="grid gap-1.5">
                    <div className="flex items-center justify-between gap-3">
                      <Label htmlFor="baseUrl">其它 BaseURL</Label>
                      <span className="text-[11px] text-muted-foreground">可选 · 适用于远程网关</span>
                    </div>
                    <Input
                      autoComplete="url"
                      className="h-10 font-mono text-sm"
                      disabled={mutation.isPending}
                      id="baseUrl"
                      onChange={(event) => {
                        setBaseUrl(event.target.value)
                        if (!mutation.isPending) mutation.reset()
                      }}
                      placeholder="https://gateway.example.com"
                      spellCheck={false}
                      value={baseUrl}
                    />
                  </div>

                  <div className="grid gap-1.5">
                    <Label htmlFor="sk">Secret Key</Label>
                    <Input
                      aria-describedby={error ? 'connection-note login-error' : 'connection-note'}
                      aria-invalid={Boolean(error)}
                      autoComplete="off"
                      className="h-10 font-mono text-sm"
                      disabled={mutation.isPending}
                      id="sk"
                      onChange={(event) => {
                        setSk(event.target.value)
                        if (!mutation.isPending) mutation.reset()
                      }}
                      placeholder="tbk_…"
                      required
                      type="password"
                      value={sk}
                    />
                  </div>

                  <div className="grid gap-1.5">
                    <Label htmlFor="profile">档案名</Label>
                    <Input
                      autoComplete="off"
                      className="h-10 font-mono text-sm"
                      disabled={mutation.isPending}
                      id="profile"
                      onChange={(event) => {
                        setName(event.target.value)
                        if (!mutation.isPending) mutation.reset()
                      }}
                      value={name}
                    />
                    <p className="text-[11px] text-muted-foreground">
                      对应
                      {' '}
                      <code className="font-mono">tb --profile</code>
                      ；同名档案会被更新。
                    </p>
                  </div>

                  <div
                    className="flex items-start gap-2.5 rounded-md border border-primary/20 bg-primary/[0.045] px-3 py-2.5"
                    id="connection-note"
                  >
                    {mutation.isPending
                      ? (
                          <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin text-primary" />
                        )
                      : (
                          <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />
                        )}
                    <p
                      aria-live="polite"
                      className="min-w-0 text-[11px] leading-5 text-muted-foreground"
                    >
                      {mutation.isPending
                        ? (
                            <>
                              正在读取
                              {' '}
                              <span className="break-all font-mono text-foreground">
                                {target}
                                /~help
                              </span>
                              {' '}
                              验证连接与权限…
                            </>
                          )
                        : (
                            <>只读取 /~help 完成验证；凭据保存在本浏览器，请仅在受信任设备使用。</>
                          )}
                    </p>
                  </div>

                  {error && (
                    <div
                      className="rounded-md border border-destructive/40 bg-destructive/[0.07] px-3 py-2.5 text-xs leading-5 text-destructive"
                      id="login-error"
                      role="alert"
                    >
                      {connectionErrorMessage(error)}
                    </div>
                  )}

                  <Button
                    className="mt-1 w-full"
                    disabled={mutation.isPending || sk.trim() === ''}
                    size="lg"
                    type="submit"
                  >
                    {mutation.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />}
                    {mutation.isPending ? '正在验证…' : '验证并接入'}
                    {!mutation.isPending && <ArrowRight className="ml-auto" />}
                  </Button>
                </form>
              </section>
            )}
          </div>

          <p className="mt-5 text-center font-mono text-[11px] text-muted-foreground">
            fetch-compatible · self-describing · credential-scoped
          </p>
        </section>
      </main>
    </div>
  )
}
