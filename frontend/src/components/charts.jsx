/**
 * Inline SVG charts. No charting dependency: these are small, fixed-purpose
 * marks where a library would add weight without adding accuracy. Every chart
 * draws from currentColor or a severity token so both themes work unmodified.
 */

import { useMemo, useState } from 'react';
import { cx } from './ui';
import { formatNumber } from '../lib/format';

const SEV_FILL = {
  critical: 'fill-critical',
  high: 'fill-high',
  medium: 'fill-medium',
  low: 'fill-low',
  info: 'fill-info',
};

/* ------------------------------------------------------------ Column chart */
export function ColumnChart({ points = [], height = 120, formatLabel, className = '' }) {
  const [hover, setHover] = useState(null);
  const max = Math.max(...points.map((p) => p.value), 1);
  const gap = 2;

  if (!points.length) {
    return <div className={cx('flex items-center justify-center text-xs text-ink-3', className)} style={{ height }}>No data in range</div>;
  }

  const width = 100;
  const barWidth = (width - gap * (points.length - 1)) / points.length;

  return (
    <div className={cx('relative', className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="w-full block"
        style={{ height }}
      >
        {[0.25, 0.5, 0.75, 1].map((ratio) => (
          <line
            key={ratio}
            x1="0"
            x2={width}
            y1={height - height * ratio}
            y2={height - height * ratio}
            className="stroke-line"
            strokeWidth="0.5"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {points.map((point, index) => {
          const barHeight = Math.max((point.value / max) * (height - 6), point.value > 0 ? 1.5 : 0);
          return (
            <rect
              key={index}
              x={index * (barWidth + gap)}
              y={height - barHeight}
              width={barWidth}
              height={barHeight}
              rx="0.6"
              className={cx(
                'transition-opacity duration-120',
                hover === index ? 'fill-accent' : 'fill-accent/55',
              )}
              onMouseEnter={() => setHover(index)}
              onMouseLeave={() => setHover(null)}
            />
          );
        })}
      </svg>
      {hover !== null && (
        <div className="absolute top-0 left-0 right-0 flex justify-center pointer-events-none">
          <span className="px-2 py-1 rounded bg-raised border border-line-strong shadow-pop text-2xs text-ink whitespace-nowrap">
            {formatLabel ? formatLabel(points[hover]) : `${formatNumber(points[hover].value)} events`}
          </span>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------- Stacked severity bar */
export function StackedBar({ segments = [], height = 8, className = '', showLegend = false }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0) || 1;
  return (
    <div className={className}>
      <div className="flex rounded-full overflow-hidden bg-line" style={{ height }}>
        {segments.map((segment) => (
          <div
            key={segment.label}
            className={cx(
              segment.label === 'critical' && 'bg-critical',
              segment.label === 'high' && 'bg-high',
              segment.label === 'medium' && 'bg-medium',
              segment.label === 'low' && 'bg-low',
              segment.label === 'info' && 'bg-info',
              !SEV_FILL[segment.label] && 'bg-accent',
            )}
            style={{ width: `${(segment.value / total) * 100}%` }}
            title={`${segment.label}: ${segment.value}`}
          />
        ))}
      </div>
      {showLegend && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2">
          {segments.map((segment) => (
            <span key={segment.label} className="inline-flex items-center gap-1.5 text-2xs text-ink-2">
              <span
                className={cx(
                  'w-2 h-2 rounded-[2px]',
                  segment.label === 'critical' && 'bg-critical',
                  segment.label === 'high' && 'bg-high',
                  segment.label === 'medium' && 'bg-medium',
                  segment.label === 'low' && 'bg-low',
                  segment.label === 'info' && 'bg-info',
                )}
              />
              {segment.label}
              <span className="tnum text-ink-3">{segment.value}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------ Horizontal bars */
export function BarList({ items = [], valueLabel, className = '', tone = 'accent', max: maxOverride }) {
  const max = maxOverride || Math.max(...items.map((i) => i.value), 1);
  if (!items.length) {
    return <p className={cx('text-xs text-ink-3 py-4 text-center', className)}>No data</p>;
  }
  return (
    <ul className={cx('space-y-1.5', className)}>
      {items.map((item) => (
        <li key={item.label} className="group">
          <div className="flex items-baseline justify-between gap-3 mb-1">
            <span className="text-xs text-ink truncate" title={item.label}>
              {item.label}
            </span>
            <span className="text-2xs tnum text-ink-3 shrink-0">
              {formatNumber(item.value)}
              {valueLabel ? ` ${valueLabel}` : ''}
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-line overflow-hidden">
            <div
              className={cx(
                'h-full rounded-full transition-all duration-300',
                tone === 'accent' && 'bg-accent/70 group-hover:bg-accent',
                tone === 'critical' && 'bg-critical/70 group-hover:bg-critical',
              )}
              style={{ width: `${(item.value / max) * 100}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

/* ----------------------------------------------------------------- Donut */
export function Donut({ segments = [], size = 132, thickness = 14, centerLabel, centerValue }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;

  const arcs = useMemo(() => {
    let offset = 0;
    return segments.map((segment) => {
      const fraction = total ? segment.value / total : 0;
      const arc = {
        ...segment,
        dash: fraction * circumference,
        offset,
      };
      offset += fraction * circumference;
      return arc;
    });
  }, [segments, total, circumference]);

  const colorClass = (label) =>
    ({
      critical: 'stroke-critical',
      high: 'stroke-high',
      medium: 'stroke-medium',
      low: 'stroke-low',
      info: 'stroke-info',
      compliant: 'stroke-success',
      partial: 'stroke-medium',
      gap: 'stroke-critical',
      na: 'stroke-info',
    })[label] || 'stroke-accent';

  return (
    <div className="relative inline-flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={thickness}
          className="stroke-line"
        />
        {arcs.map((arc) => (
          <circle
            key={arc.label}
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            strokeWidth={thickness}
            strokeDasharray={`${arc.dash} ${circumference - arc.dash}`}
            strokeDashoffset={-arc.offset}
            className={colorClass(arc.label)}
          >
            <title>{`${arc.label}: ${arc.value}`}</title>
          </circle>
        ))}
      </svg>
      {(centerValue !== undefined || centerLabel) && (
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-semibold tnum text-ink leading-none">{centerValue}</span>
          {centerLabel && <span className="text-2xs text-ink-3 mt-1">{centerLabel}</span>}
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------- Sparkline */
export function Sparkline({ values = [], width = 90, height = 24, className = '' }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const step = width / (values.length - 1);
  const path = values
    .map((value, index) => `${index === 0 ? 'M' : 'L'}${(index * step).toFixed(2)},${(height - ((value - min) / span) * height).toFixed(2)}`)
    .join(' ');

  return (
    <svg width={width} height={height} className={cx('overflow-visible', className)} aria-hidden="true">
      <path d={path} fill="none" className="stroke-accent" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  );
}

/* ------------------------------------------------------------- Score ring */
export function ScoreRing({ score = 0, size = 76, label }) {
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const filled = (Math.min(Math.max(score, 0), 100) / 100) * circumference;
  const tone =
    score >= 85 ? 'stroke-success' : score >= 65 ? 'stroke-medium' : 'stroke-critical';

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" strokeWidth="7" className="stroke-line" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference - filled}`}
          className={tone}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-md font-semibold tnum text-ink leading-none">{score}%</span>
        {label && <span className="text-2xs text-ink-3 mt-0.5">{label}</span>}
      </div>
    </div>
  );
}
