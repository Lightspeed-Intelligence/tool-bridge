import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  EXPIRY_OPTIONS,
  type ExpiryPreset,
  type MyKeyFormState,
} from './myKeyConfig'

/**
 * 签发 / 编辑「我的 key」的表单本体:只有描述与有效期。
 *
 * **刻意没有 scope 选择器** —— 权限由服务端钉死成登录默认那套,给个选择器只会让用户
 * 以为自己能改。
 */
export function MyKeyFormFields({
  disabled,
  idPrefix,
  onChange,
  state,
}: {
  disabled: boolean
  /** 同页可能同时存在签发与编辑两个表单,label 的 htmlFor 需要各自唯一。 */
  idPrefix: string
  onChange: (next: MyKeyFormState) => void
  state: MyKeyFormState
}) {
  return (
    <div className="grid gap-4">
      <div className="grid gap-1.5">
        <Label className="text-xs" htmlFor={`${idPrefix}-description`}>
          描述（可选）
        </Label>
        <Textarea
          autoComplete="off"
          className="min-h-16 text-sm"
          disabled={disabled}
          id={`${idPrefix}-description`}
          onChange={event => onChange({ ...state, description: event.target.value })}
          placeholder="用在哪里，例如：办公笔记本的 tb CLI"
          spellCheck={false}
          value={state.description}
        />
        <p className="text-[11px] leading-5 text-muted-foreground">
          只用于你自己在列表里认出这把 key。
        </p>
      </div>

      <div className="grid gap-1.5">
        <Label className="text-xs" htmlFor={`${idPrefix}-expiry`}>
          有效期
        </Label>
        <Select
          disabled={disabled}
          onValueChange={value => onChange({ ...state, preset: value as ExpiryPreset })}
          value={state.preset}
        >
          <SelectTrigger className="w-full text-sm" id={`${idPrefix}-expiry`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {EXPIRY_OPTIONS.map(option => (
              <SelectItem className="text-sm" key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {state.preset === 'custom' && (
          <Input
            aria-label="过期日期"
            className="text-sm"
            disabled={disabled}
            onChange={event => onChange({ ...state, customDate: event.target.value })}
            type="date"
            value={state.customDate}
          />
        )}
        <p className="text-[11px] leading-5 text-muted-foreground">
          {state.preset === 'forever'
            ? '永久有效的 key 不会自动失效，只能由你手动撤销。'
            : '到期后这把 key 会自动失效，届时重新签发一把即可。'}
        </p>
      </div>
    </div>
  )
}
