import { CheckCircle2, CircleDashed, KeyRound, Loader2, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { toast } from 'sonner'
import type { CredentialDomainState } from '@/lib/types'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useInvoke, useMyCredentials } from '@/lib/queries'
import { ConfirmAction } from '@/components/ConfirmAction'
import { EmptyState } from '@/components/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'

/** 填/换个人 token 弹窗:提交后即弃,明文不回显、不入 URL、不进日志。 */
function SetTokenDialog({
  domain,
  open,
  onOpenChange,
}: {
  domain: CredentialDomainState | null
  onOpenChange: (open: boolean) => void
  open: boolean
}) {
  const invoke = useInvoke()
  const qc = useQueryClient()
  const [value, setValue] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const close = (next: boolean) => {
    if (invoke.isPending) return
    onOpenChange(next)
    if (!next) {
      setValue('')
      setErr(null)
      invoke.reset()
    }
  }

  const submit = async () => {
    if (domain === null) return
    if (value.trim() === '') {
      setErr('请粘贴你的个人 token')
      return
    }
    setErr(null)
    await invoke
      .mutateAsync(
        {
          commandPath: 'system/usercred/set',
          args: { domain: domain.domain, value: value.trim() },
        },
        {
          onSuccess: () => {
            toast.success(`已保存 ${domain.domain} 的个人凭证`)
            setValue('')
            onOpenChange(false)
            qc.invalidateQueries({ queryKey: ['tb'] })
          },
          onError: e => setErr(e.message),
        },
      )
      .catch(() => undefined)
  }

  return (
    <Dialog onOpenChange={close} open={open}>
      <DialogContent className="p-4 sm:max-w-lg sm:p-6" showCloseButton={!invoke.isPending}>
        <DialogHeader>
          <DialogTitle className="text-base">
            {domain?.configured ? '更换' : '添加'}
            个人凭证 ·
            {' '}
            {domain?.domain}
          </DialogTitle>
          <DialogDescription>
            粘贴你本人的 token。它加密保存，只用于以你的身份调用该域的上游；服务端永不回显，也不会写进日志。
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-2">
          <Label className="text-xs" htmlFor="usercred-value">
            个人 token
          </Label>
          <Textarea
            autoComplete="off"
            className="min-h-24 font-mono text-xs"
            id="usercred-value"
            onChange={(event) => {
              setValue(event.target.value)
              setErr(null)
            }}
            placeholder="粘贴你的云效 Personal Access Token"
            spellCheck={false}
            value={value}
          />
          {err && (
            <p className="text-xs text-destructive" role="alert">
              {err}
            </p>
          )}
          {domain !== null && domain.nodePaths.length > 0 && (
            <p className="text-[11px] leading-5 text-muted-foreground">
              将用于：
              {domain.nodePaths.map(p => (
                <code className="mx-0.5 rounded border bg-muted/20 px-1 py-0.5 font-mono" key={p}>
                  {p}
                </code>
              ))}
            </p>
          )}
        </div>

        <DialogFooter className="border-t pt-4">
          <Button disabled={invoke.isPending} onClick={() => close(false)} variant="outline">
            取消
          </Button>
          <Button disabled={invoke.isPending} onClick={() => void submit()}>
            {invoke.isPending && <Loader2 className="animate-spin" />}
            {invoke.isPending ? '正在保存' : '保存并即时清除明文'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DomainRow({
  domain,
  onEdit,
  onClear,
}: {
  domain: CredentialDomainState
  onClear: (domain: CredentialDomainState) => Promise<void>
  onEdit: (domain: CredentialDomainState) => void
}) {
  return (
    <div className="flex flex-col gap-3 border-b px-4 py-4 last:border-b-0 sm:flex-row sm:items-center">
      <span
        className={`grid size-9 shrink-0 place-items-center rounded-lg border ${
          domain.configured
            ? 'border-ok/25 bg-ok/[0.05] text-ok'
            : 'border-muted-foreground/20 bg-muted/15 text-muted-foreground'
        }`}
      >
        {domain.configured ? <CheckCircle2 className="size-4" /> : <CircleDashed className="size-4" />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <code className="font-mono text-sm font-medium">{domain.domain}</code>
          <Badge
            className={
              domain.configured
                ? 'border-ok/30 text-ok'
                : 'border-muted-foreground/30 text-muted-foreground'
            }
            variant="outline"
          >
            {domain.configured ? '已用个人凭证' : '回落管理员默认'}
          </Badge>
        </div>
        <p className="mt-1 truncate text-xs text-muted-foreground">
          {domain.description ?? '上游凭证域'}
          {domain.updatedAt ? ` · 更新于 ${new Date(domain.updatedAt).toLocaleString()}` : ''}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Button onClick={() => onEdit(domain)} size="sm" variant={domain.configured ? 'outline' : 'default'}>
          {domain.configured ? '更换' : '添加凭证'}
        </Button>
        {domain.configured && (
          <ConfirmAction
            actionLabel="清除"
            description={<p>清除后该域将回落到管理员默认凭证，你的写操作不再以本人身份落地。</p>}
            onConfirm={() => onClear(domain)}
            title={`清除 ${domain.domain} 的个人凭证?`}
            trigger={(
              <Button aria-label={`清除 ${domain.domain}`} size="icon-sm" variant="ghost">
                <Trash2 className="text-destructive" />
              </Button>
            )}
          />
        )}
      </div>
    </div>
  )
}

/**
 * 「我的凭证」:飞书登录用户自助管理个人上游凭证(system/usercred)。
 * 列出所有可配域(节点声明 credentialDomain),配了个人 token 的以本人身份落地,
 * 未配的回落管理员默认。凭证只写不读,明文一次性提交、即时清除。
 */
export function MyCredentialsPage() {
  const list = useMyCredentials()
  const invoke = useInvoke()
  const qc = useQueryClient()
  const [editing, setEditing] = useState<CredentialDomainState | null>(null)
  const [open, setOpen] = useState(false)

  const items = list.data?.items ?? []
  const configured = items.filter(d => d.configured).length

  const edit = (domain: CredentialDomainState) => {
    setEditing(domain)
    setOpen(true)
  }

  const clear = async (domain: CredentialDomainState) => {
    try {
      await invoke.mutateAsync({
        commandPath: 'system/usercred/delete',
        args: { domain: domain.domain },
      })
      toast.success(`已清除 ${domain.domain} 的个人凭证`)
      await qc.invalidateQueries({ queryKey: ['tb'] })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '清除个人凭证失败')
      throw error
    }
  }

  return (
    <div className="mx-auto max-w-4xl px-4 py-5 sm:px-6 sm:py-6 lg:px-8 lg:py-8">
      <PageHeader
        description="为支持个人身份的上游填入你本人的 token。配了就以你的身份落地(如云效评论/写操作),没配则沿用管理员默认。"
        eyebrow="ME / CREDENTIALS"
        title="我的凭证"
      />

      <section className="mt-6 flex items-center gap-3 rounded-xl border border-primary/20 bg-primary/[0.03] px-4 py-3.5">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-primary/25 bg-primary/8 text-primary">
          <ShieldCheck className="size-4" />
        </span>
        <p className="text-xs leading-5 text-muted-foreground">
          凭证加密保存、只写不读,提交后明文即弃。你只能读写自己的凭证,管理员也看不到明文。
        </p>
      </section>

      <section className="mt-4 overflow-hidden rounded-xl border bg-card/70">
        <div className="flex items-center justify-between gap-3 border-b bg-muted/10 px-4 py-3">
          <div className="flex items-center gap-3">
            <div className="grid size-8 shrink-0 place-items-center rounded-md border bg-background text-primary">
              <KeyRound className="size-4" />
            </div>
            <div>
              <h2 className="text-sm font-medium">可配置的凭证域</h2>
              <p className="text-xs text-muted-foreground">
                {items.length}
                {' '}
                个域,已配置
                {' '}
                {configured}
                {' '}
                个
              </p>
            </div>
          </div>
          <Button
            aria-label="刷新"
            onClick={() => void list.refetch()}
            size="icon-sm"
            variant="ghost"
          >
            <RefreshCw />
          </Button>
        </div>

        {list.isPending
          ? (
              <div className="grid gap-3 p-4">
                <Skeleton className="h-14 w-full" />
                <Skeleton className="h-14 w-5/6" />
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
                  title="无法加载凭证域"
                  tone="danger"
                >
                  <p>{list.error.message}</p>
                </EmptyState>
              )
            : items.length === 0
              ? (
                  <EmptyState className="m-4" icon={KeyRound} title="暂无可配置的凭证域">
                    <p>还没有上游节点开放个人凭证。需要时请联系管理员为相应节点标注 credentialDomain。</p>
                  </EmptyState>
                )
              : (
                  <div>
                    {items.map(domain => (
                      <DomainRow domain={domain} key={domain.domain} onClear={clear} onEdit={edit} />
                    ))}
                  </div>
                )}
      </section>

      <SetTokenDialog domain={editing} onOpenChange={setOpen} open={open} />
    </div>
  )
}
