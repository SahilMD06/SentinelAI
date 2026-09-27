/**
 * SentinelAI mark — a shield whose interior is a circuit die: the protective
 * boundary and the reasoning core drawn as one figure. Purely geometric, no
 * gradients or glows, so it holds up at 20px in a collapsed rail and at 96px
 * on the sign-in card.
 */

export function LogoMark({ size = 28, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      className={className}
      role="img"
      aria-label="SentinelAI"
    >
      {/* Shield body */}
      <path
        d="M16 2.4 27.2 6.3v9.1c0 6.6-4.5 12-11.2 14.2C9.3 27.4 4.8 22 4.8 15.4V6.3L16 2.4Z"
        className="fill-accent/10 stroke-accent"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      {/* Die */}
      <rect
        x="11.4"
        y="11.4"
        width="9.2"
        height="9.2"
        rx="1.3"
        className="stroke-accent"
        strokeWidth="1.5"
      />
      <rect x="14.4" y="14.4" width="3.2" height="3.2" rx="0.6" className="fill-accent" />
      {/* Circuit traces leaving the die on all four sides */}
      <g className="stroke-accent" strokeWidth="1.35" strokeLinecap="round">
        <path d="M16 7.4v4" />
        <path d="M16 20.6v3.8" />
        <path d="M7.6 16h3.8" />
        <path d="M20.6 16h3.8" />
        <path d="M13 11.4V9.2" />
        <path d="M19 20.6v2.2" />
      </g>
      {/* Trace terminals */}
      <g className="fill-accent">
        <circle cx="16" cy="7" r="1.15" />
        <circle cx="7.2" cy="16" r="1.15" />
        <circle cx="24.8" cy="16" r="1.15" />
        <circle cx="16" cy="24.8" r="1.15" />
      </g>
    </svg>
  );
}

export function Wordmark({ className = '' }) {
  return (
    <span className={`font-semibold tracking-tight text-ink leading-none ${className}`}>
      Sentinel<span className="text-accent">AI</span>
    </span>
  );
}

export function Logo({ collapsed = false, size = 26 }) {
  return (
    <div className="flex items-center gap-2.5 min-w-0">
      <LogoMark size={size} className="shrink-0" />
      {!collapsed && (
        <span className="flex flex-col min-w-0 leading-none">
          <Wordmark className="text-[15px]" />
          <span className="text-2xs text-ink-3 mt-[3px] tracking-[0.06em] uppercase truncate">
            Security Operations
          </span>
        </span>
      )}
    </div>
  );
}

export default Logo;
