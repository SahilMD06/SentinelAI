import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { IconCheck, IconClose, IconLock } from './icons';
import {
  CONTROL_STATUS_STYLE,
  SEVERITY_DOT,
  SEVERITY_STYLE,
  STATUS_LABEL,
  STATUS_STYLE,
  titleCase,
} from '../lib/format';

export const cx = (...parts) => parts.filter(Boolean).join(' ');

/* -------------------------------------------------------------- Button */
const VARIANTS = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  ghost: 'btn-ghost',
  danger: 'btn-danger',
};

export function Button({
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  children,
  className = '',
  locked = false,
  lockedReason = 'Your role does not permit this action',
  disabled,
  ...rest
}) {
  const button = (
    <button
      type="button"
      className={cx(VARIANTS[variant], size === 'sm' && 'btn-sm', className)}
      disabled={disabled || locked}
      {...rest}
    >
      {locked ? <IconLock size={size === 'sm' ? 12 : 13} /> : Icon ? <Icon size={size === 'sm' ? 13 : 14} /> : null}
      {children}
    </button>
  );
  return locked ? <Tooltip label={lockedReason}>{button}</Tooltip> : button;
}

/* ------------------------------------------------------------- Tooltip */
export function Tooltip({ label, children, side = 'top' }) {
  const [open, setOpen] = useState(false);
  if (!label) return children;
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          className={cx(
            'absolute z-50 whitespace-normal w-max max-w-[260px] px-2 py-1 rounded',
            'bg-raised border border-line-strong shadow-pop text-xs text-ink',
            'pointer-events-none animate-fade-in',
            side === 'top' && 'bottom-full left-1/2 -translate-x-1/2 mb-1.5',
            side === 'bottom' && 'top-full left-1/2 -translate-x-1/2 mt-1.5',
            side === 'left' && 'right-full top-1/2 -translate-y-1/2 mr-1.5',
            side === 'right' && 'left-full top-1/2 -translate-y-1/2 ml-1.5',
          )}
        >
          {label}
        </span>
      )}
    </span>
  );
}

/* --------------------------------------------------------------- Panel */
export function Panel({ title, subtitle, actions, children, className = '', bodyClass = '', dense }) {
  return (
    <section className={cx('panel flex flex-col min-h-0', className)}>
      {(title || actions) && (
        <header className="panel-header shrink-0">
          <div className="min-w-0">
            {title && <h2 className="panel-title truncate">{title}</h2>}
            {subtitle && <p className="text-2xs text-ink-3 truncate mt-px">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-1.5 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={cx(dense ? '' : 'p-4', 'min-h-0', bodyClass)}>{children}</div>
    </section>
  );
}

/* --------------------------------------------------------------- Badge */
export function SeverityBadge({ value, className = '' }) {
  if (!value) return null;
  return (
    <span className={cx('badge', SEVERITY_STYLE[value] || SEVERITY_STYLE.info, className)}>
      {value}
    </span>
  );
}

export function SeverityDot({ value, className = '' }) {
  return (
    <span
      className={cx('inline-block w-[7px] h-[7px] rounded-full shrink-0', SEVERITY_DOT[value] || SEVERITY_DOT.info, className)}
      title={value}
    />
  );
}

export function StatusBadge({ value, className = '' }) {
  if (!value) return null;
  return (
    <span className={cx('badge', STATUS_STYLE[value] || 'badge-outline', className)}>
      {STATUS_LABEL[value] || titleCase(value)}
    </span>
  );
}

export function ControlStatusBadge({ value }) {
  return (
    <span className={cx('badge', CONTROL_STATUS_STYLE[value] || 'badge-outline')}>
      {value === 'na' ? 'N/A' : value}
    </span>
  );
}

export function Chip({ children, className = '', onRemove }) {
  return (
    <span className={cx('chip', className)}>
      {children}
      {onRemove && (
        <button type="button" onClick={onRemove} className="text-ink-3 hover:text-ink" aria-label="Remove">
          <IconClose size={10} />
        </button>
      )}
    </span>
  );
}

/* ------------------------------------------------------------ Risk meter */
export function RiskMeter({ score = 0, size = 'md', showLabel = true }) {
  const tone =
    score >= 80 ? 'bg-critical' : score >= 60 ? 'bg-high' : score >= 35 ? 'bg-medium' : 'bg-low';
  const width = size === 'sm' ? 'w-14' : 'w-24';
  return (
    <div className="flex items-center gap-2">
      <div className={cx('h-1.5 rounded-full bg-line overflow-hidden shrink-0', width)}>
        <div className={cx('h-full rounded-full', tone)} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      {showLabel && <span className="text-xs tnum text-ink-2 shrink-0">{score}</span>}
    </div>
  );
}

/* ----------------------------------------------------------- Stat tile */
export function StatTile({ label, value, sub, tone = 'default', icon: Icon, onClick }) {
  const toneClass = {
    default: 'text-ink',
    critical: 'text-critical',
    high: 'text-high',
    medium: 'text-medium',
    success: 'text-success',
    accent: 'text-accent',
  }[tone];

  const Wrapper = onClick ? 'button' : 'div';
  return (
    <Wrapper
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      className={cx(
        'panel px-3.5 py-3 text-left flex flex-col gap-1 min-w-0',
        onClick && 'hover:border-line-strong transition-colors duration-120',
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="section-label truncate">{label}</span>
        {Icon && <Icon size={14} className="text-ink-3 shrink-0" />}
      </div>
      <span className={cx('text-2xl font-semibold tnum leading-none', toneClass)}>{value}</span>
      {sub && <span className="text-2xs text-ink-3 truncate">{sub}</span>}
    </Wrapper>
  );
}

/* --------------------------------------------------------------- Tabs */
export function Tabs({ tabs, active, onChange, className = '' }) {
  return (
    <div className={cx('flex items-center gap-0.5 border-b border-line overflow-x-auto', className)}>
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          onClick={() => onChange(tab.key)}
          className={cx('tab shrink-0', active === tab.key && 'tab-active')}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span className="ml-1.5 text-2xs tnum text-ink-3">{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------- Inputs */
export function Field({ label, hint, error, children, required, className = '' }) {
  return (
    <label className={cx('flex flex-col gap-1', className)}>
      {label && (
        <span className="text-xs font-medium text-ink-2">
          {label}
          {required && <span className="text-critical ml-0.5">*</span>}
        </span>
      )}
      {children}
      {error ? (
        <span className="text-2xs text-critical">{error}</span>
      ) : hint ? (
        <span className="text-2xs text-ink-3">{hint}</span>
      ) : null}
    </label>
  );
}

export function Select({ options, className = '', ...rest }) {
  return (
    <select className={cx('field pr-7 appearance-none cursor-pointer', className)} {...rest}>
      {options.map((option) =>
        typeof option === 'string' ? (
          <option key={option} value={option}>
            {titleCase(option)}
          </option>
        ) : (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ),
      )}
    </select>
  );
}

export function Checkbox({ checked, onChange, disabled, label, hint, id }) {
  return (
    <label
      htmlFor={id}
      className={cx(
        'flex items-start gap-2.5 group',
        disabled ? 'cursor-not-allowed' : 'cursor-pointer',
      )}
    >
      <span
        className={cx(
          'mt-px w-[15px] h-[15px] rounded-[3px] border flex items-center justify-center shrink-0 transition-colors duration-120',
          checked ? 'bg-accent border-accent text-white' : 'border-line-strong bg-surface',
          disabled && 'opacity-45',
          !disabled && !checked && 'group-hover:border-accent',
        )}
      >
        {checked && <IconCheck size={11} strokeWidth={2.6} />}
      </span>
      <input
        id={id}
        type="checkbox"
        className="sr-only"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange?.(e.target.checked)}
      />
      <span className="min-w-0">
        {label && (
          <span
            className={cx(
              'block text-sm',
              checked ? 'text-ink-3 line-through decoration-line-strong' : 'text-ink',
            )}
          >
            {label}
          </span>
        )}
        {hint && <span className="block text-2xs text-ink-3 mt-0.5 leading-relaxed">{hint}</span>}
      </span>
    </label>
  );
}

/* --------------------------------------------------------------- Modal */
export function Modal({ open, onClose, title, subtitle, children, footer, width = 'max-w-lg' }) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => e.key === 'Escape' && onClose?.();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[8vh] animate-fade-in">
      <div className="absolute inset-0 bg-black/45" onClick={onClose} aria-hidden="true" />
      <div
        role="dialog"
        aria-modal="true"
        className={cx(
          'relative w-full bg-surface border border-line-strong rounded-lg shadow-pop',
          'flex flex-col max-h-[80vh] animate-slide-up',
          width,
        )}
      >
        <header className="flex items-start justify-between gap-4 px-4 py-3 border-b border-line shrink-0">
          <div className="min-w-0">
            <h2 className="text-md font-semibold text-ink">{title}</h2>
            {subtitle && <p className="text-xs text-ink-3 mt-0.5">{subtitle}</p>}
          </div>
          <button type="button" onClick={onClose} className="btn-ghost btn-sm -mr-1" aria-label="Close">
            <IconClose size={14} />
          </button>
        </header>
        <div className="p-4 overflow-y-auto scroll-y">{children}</div>
        {footer && (
          <footer className="flex items-center justify-end gap-2 px-4 py-3 border-t border-line shrink-0">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- Toast */
const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const counter = useRef(0);

  const dismiss = useCallback((id) => setToasts((list) => list.filter((t) => t.id !== id)), []);

  const push = useCallback(
    (message, tone = 'info', ttl = 5000) => {
      counter.current += 1;
      const id = counter.current;
      setToasts((list) => [...list, { id, message, tone }]);
      if (ttl) setTimeout(() => dismiss(id), ttl);
      return id;
    },
    [dismiss],
  );

  const value = useMemo(
    () => ({
      push,
      success: (m) => push(m, 'success'),
      error: (m) => push(m, 'error', 7000),
      info: (m) => push(m, 'info'),
      dismiss,
    }),
    [push, dismiss],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 w-[340px] max-w-[calc(100vw-2rem)]">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role="status"
            className={cx(
              'flex items-start gap-2.5 px-3 py-2.5 rounded-md border shadow-pop bg-raised animate-slide-up',
              toast.tone === 'success' && 'border-success/40',
              toast.tone === 'error' && 'border-critical/40',
              toast.tone === 'info' && 'border-line-strong',
            )}
          >
            <span
              className={cx(
                'w-1 self-stretch rounded-full shrink-0',
                toast.tone === 'success' && 'bg-success',
                toast.tone === 'error' && 'bg-critical',
                toast.tone === 'info' && 'bg-accent',
              )}
            />
            <p className="text-sm text-ink flex-1 leading-snug">{toast.message}</p>
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              className="text-ink-3 hover:text-ink shrink-0"
              aria-label="Dismiss"
            >
              <IconClose size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast must be used inside <ToastProvider>');
  return context;
}

/* ------------------------------------------------------- State displays */
export function Spinner({ size = 14, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      className={cx('animate-spin', className)}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.5" fill="none" opacity="0.2" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        fill="none"
      />
    </svg>
  );
}

export function Loading({ label = 'Loading', className = '' }) {
  return (
    <div className={cx('flex items-center justify-center gap-2 py-10 text-ink-3 text-sm', className)}>
      <Spinner />
      {label}…
    </div>
  );
}

export function Empty({ title = 'Nothing here', hint, icon: Icon, action, className = '' }) {
  return (
    <div className={cx('flex flex-col items-center justify-center text-center py-12 px-6 gap-2', className)}>
      {Icon && <Icon size={22} className="text-ink-3" />}
      <p className="text-sm font-medium text-ink-2">{title}</p>
      {hint && <p className="text-xs text-ink-3 max-w-sm leading-relaxed">{hint}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, className = '' }) {
  return (
    <div className={cx('flex flex-col items-center justify-center text-center py-10 px-6 gap-2', className)}>
      <p className="text-sm font-medium text-critical">Request failed</p>
      <p className="text-xs text-ink-3 max-w-md leading-relaxed">
        {error?.message || String(error || 'Unknown error')}
      </p>
      {onRetry && (
        <Button size="sm" onClick={onRetry} className="mt-1">
          Retry
        </Button>
      )}
    </div>
  );
}

export function SkeletonRows({ rows = 6, className = '' }) {
  return (
    <div className={cx('space-y-2 p-4', className)}>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton h-7" style={{ opacity: 1 - index * 0.09 }} />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------ Read-only */
export function LockedNotice({ children = 'Read-only role — write actions are disabled.' }) {
  return (
    <div className="flex items-start gap-2 px-3 py-2 rounded border border-line bg-sunken text-xs text-ink-2">
      <IconLock size={13} className="mt-px shrink-0 text-ink-3" />
      <span className="leading-relaxed">{children}</span>
    </div>
  );
}

/* -------------------------------------------------------- Copy to clipboard */
export function CopyButton({ value, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="text-2xs text-ink-3 hover:text-accent transition-colors duration-120"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* clipboard blocked in this context */
        }
      }}
    >
      {copied ? 'Copied' : label}
    </button>
  );
}
