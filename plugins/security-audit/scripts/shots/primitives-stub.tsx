/**
 * Stand-ins for the UI primitives the pane imports, for the screenshot harness
 * only. The real ones are page modules the studio supplies; a bare page cannot,
 * so these draw the same structure with the same design tokens.
 */
import { forwardRef, type ReactNode } from 'react'

/** Tag palette selector, as the real primitive names it. */
export type TagTone = 'outline' | 'solid' | 'neutral' | 'quiet' | 'success' | 'info' | 'warning' | 'danger'

/** One menu entry, as the real primitive names it. */
export interface MenuEntry { readonly id: string; readonly label: string }

/** A button. */
export function Button({ variant = 'ghost', size = 'md', icon, children, ...rest }: {
  variant?: string; size?: string; icon?: ReactNode; children?: ReactNode
} & Record<string, unknown>): ReactNode {
  const { ['aria-label']: ariaLabel, ['aria-busy']: ariaBusy, ...native } = rest
  return (
    <button {...native} type="button" aria-label={ariaLabel as string | undefined} aria-busy={ariaBusy as boolean | undefined} className={'st-btn st-' + variant + ' st-' + size} disabled={rest.disabled === true}>
      {icon}{children}
    </button>
  )
}

/** A read-only capsule. */
export function Tag({ tone = 'outline', children }: { tone?: TagTone; children?: ReactNode }): ReactNode {
  return <span className="st-tag" data-tone={tone}>{children}</span>
}

/** A single-line field. */
export const Input = forwardRef<HTMLInputElement, {
  value?: string; ['aria-label']?: string; placeholder?: string
  onChange?: (event: { target: { value: string } }) => void
  onKeyDown?: (event: { key: string }) => void
}>(function Input({ value, onChange, ...rest }, ref) {
  return (
    <span className="st-input-wrap">
    <input
      ref={ref}
      className="st-input"
      value={value}
      placeholder={rest.placeholder}
      aria-label={rest['aria-label']}
      onChange={event => { onChange?.({ target: { value: event.target.value } }) }}
      onKeyDown={event => { rest.onKeyDown?.({ key: event.key }) }}
    />
    </span>
  )
})

/** A tablist of modes. */
export function SegmentedControl({ value, options, onChange, label }: {
  value: string; options: readonly { value: string; label: string }[]
  onChange: (next: string) => void; label: string
}): ReactNode {
  return (
    <div role="tablist" aria-label={label} className="st-seg">
      {options.map(option => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={option.value === value}
          className="st-seg-tab"
          onClick={() => { onChange(option.value) }}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

/** A menu, drawn as its anchor alone. */
export function Menu({ anchor }: { anchor: ReactNode }): ReactNode {
  return <>{anchor}</>
}

/** A tooltip, drawn as its child alone. */
export function Tooltip({ children }: { children?: ReactNode }): ReactNode {
  return <>{children}</>
}

/** A copy affordance that never settles. */
export function useClipboardCopy(_text: string): { copied: boolean; onCopy: () => void } {
  return { copied: false, onCopy: () => {} }
}

/** One glyph. */
function glyph(path: string) {
  return ({ size = 14, className }: { size?: number; className?: string }): ReactNode => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" className={className} aria-hidden>
      <path d={path} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** The chevron. */
export const IconChevronDownOutlineRegular = glyph('M4 6l4 4 4-4')
/** The refresh arrow. */
export const IconRefreshOutlineRegular = glyph('M13 8a5 5 0 1 1-1.5-3.5M13 2v3h-3')
/** The shield. */
export const IconShieldOutlineRegular = glyph('M8 2l5 2v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4l5-2z')
