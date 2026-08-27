import {
  Copy,
  Info,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import type { MyKeyInfo } from '@/lib/types'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { formatSkDate, getSkStatus, type SkStatus } from '@/lib/skStatus'
import { useInvalidate, useInvoke, useMyKeys } from '@/lib/queries'
import { ConfirmAction } from '@/components/ConfirmAction'
import { EmptyState } from '@/components/EmptyState'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  buildMyKeyCreateArgs,
  buildMyKeyUpdateArgs,
  describeScopes,
  INITIAL_MY_KEY_FORM,
  type MyKeyFormState,
  ORIGIN_LABEL,
  toMyKeyForm,
} from './forms/myKeyConfig'
import { MyKeyFormFields } from './forms/MyKeyFormFields'

/** 复制到剪贴板 + toast;失败时提示手动复制(HTTP 或无权限下 clipboard 会抛)。 */
async function copyToClipboard(secret: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(secret)
    toast.success('明文已复制到剪贴板')
  } catch {
    toast.error('复制失败，请手动选中明文复制')
  }
}

function MyKeyStatusBadge({ status }: { status: SkStatus }) {
  if (status === 'disabled') {
    return (
      <Badge
        className="border-destructive/35 bg-destructive/[0.04] text-destructive"
        variant="outline"
      >
        <span className="size-1.5 rounded-full bg-current" />
        已禁用
      </Badge>
    )
  }
  if (status === 'expired') {
    return (
      <Badge className="border-warn/35 bg-warn/[0.04] text-warn" variant="outline">
        <span className="size-1.5 rounded-full bg-current" />
        已过期
      </Badge>
    )
  }
  return (
    <Badge className="border-ok/35 bg-ok/[0.04] text-ok" variant="outline">
      <span className="size-1.5 rounded-full bg-current" />
      有效
    </Badge>
  )
}

/** 权限摘要:每条 scope 一行「区域 + 能做什么」,不糊 JSON。 */
function ScopeLines({ scopes }: { scopes: MyKeyInfo['scopes'] }) {
  const lines = describeScopes(scopes)
  if (lines.length === 0) {
    return <span className="text-[11px] text-muted-foreground">无任何权限</span>
  }
  return (
    <div className="grid gap-1">
      {lines.map((line, index) => (
        <div className="flex items-center gap-1.5 text-[11px]" key={`${line.pattern}:${index}`}>
          <span
            className={`inline-flex items-center overflow-hidden rounded-md border ${
              line.deny ? 'border-destructive/25 bg-destructive/[0.04]' : 'border-ok/20 bg-ok/[0.035]'
            }`}
            title={line.pattern}
          >
            {line.deny && <span className="px-1.5 py-0.5 text-destructive">禁止</span>}
            <span className="px-1.5 py-0.5 font-medium">{line.label}</span>
            <span className="border-l px-1.5 py-0.5 text-muted-foreground">{line.actions}</span>
          </span>
        </div>
      ))}
    </div>
  )
}

/** 签发弹窗:只收描述与有效期;成功后把明文交给一次性结果弹窗。 */
function CreateMyKeyDialog({ onIssued }: { onIssued: (value: { id: string, secret: string }) => void }) {
  const invoke = useInvoke()
  const invalidate = useInvalidate()
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState<MyKeyFormState>(INITIAL_MY_KEY_FORM)
  const [err, setErr] = useState<string | null>(null)

  const changeOpen = (next: boolean) => {
    if (invoke.isPending) return
    setOpen(next)
    if (!next) {
      setForm(INITIAL_MY_KEY_FORM)
      setErr(null)
      invoke.reset()
    }
  }

  const submit = () => {
    let args: ReturnType<typeof buildMyKeyCreateArgs>
    try {
      args = buildMyKeyCreateArgs(form)
    } catch (buildError) {
      setErr((buildError as Error).message)
      return
    }
    invoke.mutate(
      { commandPath: 'system/my-keys/create', args },
      {
        onSuccess: (response) => {
          const data = response.json as { id: string, secret: string }
          setOpen(false)
          setForm(INITIAL_MY_KEY_FORM)
          setErr(null)
          onIssued({ id: data.id, secret: data.secret })
          void invalidate('my-keys')
          // 明文已转移到结果弹窗,立刻清掉 mutation 里的副本。
          setTimeout(() => invoke.reset(), 0)
        },
        onError: error => setErr(error.message),
      },
    )
  }

  return (
    <Dialog onOpenChange={changeOpen} open={open}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus />
          签发新 key
        </Button>
      </DialogTrigger>
      <DialogContent
        className="p-4 sm:max-w-lg sm:p-6"
        onEscapeKeyDown={event => invoke.isPending && event.preventDefault()}
        onPointerDownOutside={event => invoke.isPending && event.preventDefault()}
        showCloseButton={!invoke.isPending}
      >
        <DialogHeader>
          <DialogTitle className="text-base">签发我的 key</DialogTitle>
          <DialogDescription>
            权限固定为你的登录权限，不能自选更大范围；填个描述方便日后认出它。
          </DialogDescription>
        </DialogHeader>

        <MyKeyFormFields
          disabled={invoke.isPending}
          idPrefix="my-key-create"
          onChange={setForm}
          state={form}
        />
        {err && (
          <p
            className="rounded-md border border-destructive/30 bg-destructive/[0.04] px-3 py-2 text-xs text-destructive"
            role="alert"
          >
            {err}
          </p>
        )}

        <DialogFooter className="border-t pt-4">
          <Button
            disabled={invoke.isPending}
            onClick={() => changeOpen(false)}
            type="button"
            variant="outline"
          >
            取消
          </Button>
          <Button disabled={invoke.isPending} onClick={submit}>
            {invoke.isPending && <Loader2 className="animate-spin" />}
            {invoke.isPending ? '正在签发…' : '签发'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** 编辑弹窗:改描述、改有效期(含改回永久 → 后端收 expiresAt: '')。 */
function EditMyKeyDialog({
  editing,
  onOpenChange,
}: {
  editing: MyKeyInfo | null
  onOpenChange: (open: boolean) => void
}) {
  const invoke = useInvoke()
  const invalidate = useInvalidate()
  const [form, setForm] = useState<MyKeyFormState>(INITIAL_MY_KEY_FORM)
  const [err, setErr] = useState<string | null>(null)
  // 打开时把当前 key 的值灌进表单;用 key 的 id 作为受控重置的判据。
  const [loadedId, setLoadedId] = useState<string | null>(null)
  if (editing !== null && loadedId !== editing.id) {
    setLoadedId(editing.id)
    setForm(toMyKeyForm(editing))
    setErr(null)
  }

  const changeOpen = (next: boolean) => {
    if (invoke.isPending) return
    onOpenChange(next)
    if (!next) {
      setLoadedId(null)
      setErr(null)
      invoke.reset()
    }
  }

  const submit = () => {
    if (editing === null) return
    let args: ReturnType<typeof buildMyKeyUpdateArgs>
    try {
      args = buildMyKeyUpdateArgs(editing.id, form)
    } catch (buildError) {
      setErr((buildError as Error).message)
      return
    }
    invoke.mutate(
      { commandPath: 'system/my-keys/update', args },
      {
        onSuccess: () => {
          toast.success('已更新这把 key')
          changeOpen(false)
          void invalidate('my-keys')
        },
        onError: error => setErr(error.message),
      },
    )
  }

  return (
    <Dialog onOpenChange={changeOpen} open={editing !== null}>
      <DialogContent
        className="p-4 sm:max-w-lg sm:p-6"
        onEscapeKeyDown={event => invoke.isPending && event.preventDefault()}
        onPointerDownOutside={event => invoke.isPending && event.preventDefault()}
        showCloseButton={!invoke.isPending}
      >
        <DialogHeader>
          <DialogTitle className="text-base">编辑我的 key</DialogTitle>
          <DialogDescription>
            可以改描述和有效期。权限是固定的，改不了；需要别的权限请联系管理员。
          </DialogDescription>
        </DialogHeader>

        <MyKeyFormFields
          disabled={invoke.isPending}
          idPrefix="my-key-edit"
          onChange={setForm}
          state={form}
        />
        {err && (
          <p
            className="rounded-md border border-destructive/30 bg-destructive/[0.04] px-3 py-2 text-xs text-destructive"
            role="alert"
          >
            {err}
          </p>
        )}

        <DialogFooter className="border-t pt-4">
          <Button
            disabled={invoke.isPending}
            onClick={() => changeOpen(false)}
            type="button"
            variant="outline"
          >
            取消
          </Button>
          <Button disabled={invoke.isPending} onClick={submit}>
            {invoke.isPending && <Loader2 className="animate-spin" />}
            {invoke.isPending ? '正在保存…' : '保存'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** 一次性明文弹窗:签发后展示 + 一键复制。 */
function IssuedKeyDialog({
  issued,
  onClose,
}: {
  issued: { id: string, secret: string } | null
  onClose: () => void
}) {
  return (
    <Dialog open={issued !== null}>
      <DialogContent className="p-4 sm:p-6" showCloseButton={false}>
        <DialogHeader>
          <div className="mb-1 grid size-10 place-items-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
            <KeyRound aria-hidden="true" className="size-5" />
          </div>
          <DialogTitle className="text-base">key 已签发</DialogTitle>
          <DialogDescription>
            粘到
            {' '}
            <code className="font-mono">tb login</code>
            {' '}
            或客户端配置里即可使用。
            关闭后仍能在列表中点复制按钮重新取回。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2 rounded-lg border bg-muted/15 p-3">
          <p className="font-mono text-[11px] text-muted-foreground">{issued?.id}</p>
          <div className="flex items-start gap-2">
            <code className="min-w-0 flex-1 rounded-md border bg-background px-3 py-2.5 font-mono text-xs leading-5 break-all">
              {issued?.secret}
            </code>
            <Button
              aria-label="复制明文"
              onClick={() => {
                if (issued) void copyToClipboard(issued.secret)
              }}
              size="icon-sm"
              variant="outline"
            >
              <Copy />
            </Button>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>我已保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MyKeyRow({
  copyingId,
  invokePending,
  item,
  now,
  onCopy,
  onEdit,
  onRevoke,
}: {
  copyingId: string | null
  invokePending: boolean
  item: MyKeyInfo
  now: number
  onCopy: (key: MyKeyInfo) => void
  onEdit: (key: MyKeyInfo) => void
  onRevoke: (key: MyKeyInfo) => Promise<void>
}) {
  const status = getSkStatus(item, now)
  const copying = copyingId === item.id
  // 服务端已把来源前缀剥掉,description 只剩用户自己写的那段;登录会话 key 没有描述。
  const description = item.description ?? ''
  // 委托 key 的描述是 clientId,等宽显示以区别于人写的句子。
  const isClientId = item.origin === 'delegation'
  return (
    <TableRow className="group align-top">
      <TableCell className="py-4">
        <div className="min-w-0">
          {description === ''
            ? (
                <p className="text-sm text-muted-foreground">
                  {item.origin === 'login' ? '浏览器登录会话' : '未填写描述'}
                </p>
              )
            : (
                <p className={`text-sm font-medium ${isClientId ? 'font-mono' : ''}`}>
                  {description}
                </p>
              )}
          <div className="mt-1.5">
            <Badge className="text-[10px] text-muted-foreground" variant="outline">
              {ORIGIN_LABEL[item.origin]}
            </Badge>
          </div>
          <code className="mt-1.5 block max-w-56 truncate font-mono text-[10px] text-muted-foreground">
            {item.id}
          </code>
        </div>
      </TableCell>
      <TableCell className="py-4">
        <ScopeLines scopes={item.scopes} />
      </TableCell>
      <TableCell className="py-4">
        <div className="grid gap-1.5 text-[11px]">
          <div className="flex items-center justify-between gap-2">
            <span className="text-muted-foreground">签发</span>
            <span className="font-mono">
              {item.createdAt ? formatSkDate(item.createdAt) : '未知'}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-muted-foreground">到期</span>
            {item.expiresAt === undefined
              ? <span className="text-muted-foreground">永久</span>
              : (
                  <span
                    className={`font-mono ${status === 'expired' ? 'text-warn' : ''}`}
                    title={new Date(item.expiresAt).toLocaleString()}
                  >
                    {formatSkDate(item.expiresAt)}
                  </span>
                )}
          </div>
        </div>
      </TableCell>
      <TableCell className="py-4">
        <MyKeyStatusBadge status={status} />
      </TableCell>
      <TableCell className="py-4">
        <div className="flex justify-end gap-1">
          {item.copyable
            ? (
                <Button
                  aria-label="复制明文"
                  disabled={copying}
                  onClick={() => onCopy(item)}
                  size="icon-sm"
                  title="复制明文"
                  variant="ghost"
                >
                  {copying ? <Loader2 className="animate-spin" /> : <Copy />}
                </Button>
              )
            : (
                // 老 key 只有 hash,明文永远取不回 —— 显示禁用态并说明,而不是让人点了报错。
                <Button
                  aria-label="无法取回明文"
                  disabled
                  size="icon-sm"
                  title="此 key 签发较早，无法取回明文；请撤销后重新签发"
                  variant="ghost"
                >
                  <Copy />
                </Button>
              )}
          <Button
            aria-label="编辑"
            disabled={invokePending}
            onClick={() => onEdit(item)}
            size="icon-sm"
            title="编辑描述与有效期"
            variant="ghost"
          >
            <Pencil />
          </Button>
          <ConfirmAction
            actionLabel="撤销"
            description={(
              <p>
                撤销后使用这把 key 的 CLI / 客户端会立即失去访问权限，此操作不可撤销。
                若这是你当前浏览器的登录会话 key，撤销后需要重新登录。
              </p>
            )}
            onConfirm={() => onRevoke(item)}
            title="撤销这把 key?"
            trigger={(
              <Button aria-label="撤销" size="icon-sm" title="撤销" variant="ghost">
                <Trash2 className="text-destructive" />
              </Button>
            )}
          />
        </div>
      </TableCell>
    </TableRow>
  )
}

/**
 * 「我的 key」自助区域(`system/my-keys`;所有登录用户可用)。
 *
 * 与 admin 面的区别不只是数据源:这里**没有** owner / scope 输入 —— 服务端把 owner 钉在
 * ctx.owner、把 scopes 钉成登录默认那套,所以页面上给不出、也不该给出这些选项。
 */
export function MyKeysSection() {
  const list = useMyKeys()
  const invoke = useInvoke()
  const invalidate = useInvalidate()
  const [issued, setIssued] = useState<{ id: string, secret: string } | null>(null)
  const [editing, setEditing] = useState<MyKeyInfo | null>(null)
  const [copyingId, setCopyingId] = useState<string | null>(null)

  const items = list.data ?? []
  const now = Date.now()

  const copy = async (key: MyKeyInfo) => {
    setCopyingId(key.id)
    try {
      const response = await invoke.mutateAsync({
        commandPath: 'system/my-keys/reveal',
        args: { id: key.id },
      })
      const data = response.json as { secret: string }
      await copyToClipboard(data.secret)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '取回明文失败')
    } finally {
      setCopyingId(null)
      // 明文已用完(写进剪贴板或失败),不留 mutation 副本。
      invoke.reset()
    }
  }

  // 不吞 rejection:ConfirmAction 靠它决定失败时保留弹窗、允许重试。
  const revoke = async (key: MyKeyInfo) => {
    try {
      await invoke.mutateAsync({
        commandPath: 'system/my-keys/delete',
        args: { id: key.id },
      })
      toast.success('key 已撤销')
      await invalidate('my-keys')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '撤销失败')
      throw error
    }
  }

  return (
    <section aria-label="我的 key" className="overflow-hidden rounded-xl border bg-card/70">
      <div className="flex flex-col gap-3 border-b bg-muted/10 px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid size-8 shrink-0 place-items-center rounded-md border bg-background text-primary">
            <KeyRound aria-hidden="true" className="size-4" />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-medium">我的 key</h2>
            <p className="text-xs text-muted-foreground">
              共
              {' '}
              {items.length}
              {' '}
              把，只有你自己能看到和管理
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button
            aria-label="刷新"
            onClick={() => void list.refetch()}
            size="icon-sm"
            variant="ghost"
          >
            <RefreshCw />
          </Button>
          <CreateMyKeyDialog onIssued={setIssued} />
        </div>
      </div>

      <div className="flex items-start gap-2.5 border-b bg-primary/[0.03] px-4 py-3">
        <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-primary" />
        <p className="text-[11px] leading-5 text-muted-foreground">
          这里签发的 key 权限恒等于你的登录权限，无法自选更大范围。明文加密保存，
          只有你本人能取回；管理员也看不到。
        </p>
      </div>

      {list.isPending
        ? (
            <div className="grid gap-3 p-5">
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-4/5" />
            </div>
          )
        : list.isError
          ? (
              <EmptyState
                action={(
                  <Button onClick={() => void list.refetch()} size="sm" variant="outline">
                    <RefreshCw />
                    重试
                  </Button>
                )}
                className="m-4"
                icon={KeyRound}
                title="无法加载我的 key"
                tone="danger"
              >
                <p>{list.error.message}</p>
              </EmptyState>
            )
          : items.length === 0
            ? (
                <EmptyState className="m-4" icon={KeyRound} title="你还没有任何 key">
                  <p>从右上角签发一把，用于 tb CLI 或其它客户端接入。</p>
                </EmptyState>
              )
            : (
                <div className="overflow-x-auto">
                  <Table className="min-w-[860px]">
                    <TableHeader>
                      <TableRow className="bg-muted/15">
                        <TableHead className="w-[280px]">描述</TableHead>
                        <TableHead>权限</TableHead>
                        <TableHead className="w-[170px]">生命周期</TableHead>
                        <TableHead className="w-[100px]">状态</TableHead>
                        <TableHead className="w-[124px]">
                          <span className="sr-only">操作</span>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {items.map(item => (
                        <MyKeyRow
                          copyingId={copyingId}
                          invokePending={invoke.isPending}
                          item={item}
                          key={item.id}
                          now={now}
                          onCopy={key => void copy(key)}
                          onEdit={setEditing}
                          onRevoke={revoke}
                        />
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}

      {items.some(item => !item.copyable) && (
        <div className="flex items-start gap-2.5 border-t px-4 py-3">
          <Info aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
          <p className="text-[11px] leading-5 text-muted-foreground">
            部分 key 签发较早，服务端只存了它的哈希，明文无法取回（复制按钮为禁用态）。
            需要明文时撤销后重新签发一把。
          </p>
        </div>
      )}

      <EditMyKeyDialog editing={editing} onOpenChange={next => !next && setEditing(null)} />
      <IssuedKeyDialog issued={issued} onClose={() => setIssued(null)} />
    </section>
  )
}
