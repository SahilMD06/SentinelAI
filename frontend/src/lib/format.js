/** Formatting helpers shared across the console. */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_STYLE = {
  critical: 'bg-critical/12 text-critical border border-critical/30',
  high: 'bg-high/12 text-high border border-high/30',
  medium: 'bg-medium/12 text-medium border border-medium/30',
  low: 'bg-low/12 text-low border border-low/30',
  info: 'bg-info/12 text-info border border-info/30',
};

export const SEVERITY_DOT = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
  info: 'bg-info',
};

export const STATUS_STYLE = {
  new: 'bg-low/12 text-low border border-low/30',
  triaging: 'bg-medium/12 text-medium border border-medium/30',
  investigating: 'bg-accent/12 text-accent border border-accent/30',
  contained: 'bg-high/12 text-high border border-high/30',
  remediated: 'bg-success/12 text-success border border-success/30',
  closed: 'bg-info/10 text-ink-3 border border-line',
  false_positive: 'bg-info/10 text-ink-3 border border-line',
};

export const STATUS_LABEL = {
  new: 'New',
  triaging: 'Triaging',
  investigating: 'Investigating',
  contained: 'Contained',
  remediated: 'Remediated',
  closed: 'Closed',
  false_positive: 'False positive',
};

export const PHASE_LABEL = {
  identification: 'Identification',
  containment: 'Containment',
  eradication: 'Eradication',
  recovery: 'Recovery',
  'lessons-learned': 'Lessons learned',
};

export const CONTROL_STATUS_STYLE = {
  compliant: 'bg-success/12 text-success border border-success/30',
  partial: 'bg-medium/12 text-medium border border-medium/30',
  gap: 'bg-critical/12 text-critical border border-critical/30',
  na: 'bg-info/10 text-ink-3 border border-line',
};

export function riskTone(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

export function formatNumber(value, options = {}) {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return new Intl.NumberFormat('en-US', options).format(value);
}

export function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value < 10 && index > 0 ? 1 : 0)} ${units[index]}`;
}

export function formatDuration(ms) {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = Math.round((ms % 60000) / 1000);
  return `${minutes}m ${seconds}s`;
}

export function formatMinutes(minutes) {
  if (minutes === null || minutes === undefined) return '—';
  const abs = Math.abs(minutes);
  if (abs < 60) return `${Math.round(minutes)}m`;
  if (abs < 1440) return `${(minutes / 60).toFixed(1)}h`;
  return `${(minutes / 1440).toFixed(1)}d`;
}

export function parseUtc(value) {
  if (!value) return null;
  // The API emits naive-UTC timestamps from SQLite; without the Z suffix the
  // browser would read them as local time and every relative label would drift.
  const normalised =
    typeof value === 'string' && !/[Z+]|-\d{2}:\d{2}$/.test(value.slice(10))
      ? `${value}Z`
      : value;
  const date = new Date(normalised);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDate(value, options = {}) {
  const date = parseUtc(value);
  if (!date) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    ...options,
  }).format(date);
}

export function formatTime(value) {
  const date = parseUtc(value);
  if (!date) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function formatFullDate(value) {
  const date = parseUtc(value);
  if (!date) return '—';
  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(date);
}

export function relativeTime(value) {
  const date = parseUtc(value);
  if (!date) return '—';
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  const past = seconds >= 0;
  const abs = Math.abs(seconds);
  const units = [
    [60, 'second', 1],
    [3600, 'minute', 60],
    [86400, 'hour', 3600],
    [604800, 'day', 86400],
    [2629800, 'week', 604800],
    [31557600, 'month', 2629800],
    [Infinity, 'year', 31557600],
  ];
  for (const [limit, unit, divisor] of units) {
    if (abs < limit) {
      const count = Math.max(Math.round(abs / divisor), abs < 60 ? abs : 1);
      if (unit === 'second' && abs < 15) return past ? 'just now' : 'in a moment';
      const plural = count === 1 ? unit : `${unit}s`;
      return past ? `${count} ${plural} ago` : `in ${count} ${plural}`;
    }
  }
  return '—';
}

export function titleCase(value) {
  if (!value) return '';
  return String(value)
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function truncate(value, length = 90) {
  if (!value) return '';
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

export function initials(name) {
  if (!name) return '??';
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || '')
    .join('');
}

/** Minimal markdown → HTML for agent briefs and Copilot replies. */
export function renderMarkdown(markdown) {
  if (!markdown) return '';
  const escape = (text) =>
    text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const inline = (text) =>
    escape(text)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[\s(])_([^_]+)_(?=[\s.,)]|$)/g, '$1<em>$2</em>');

  const out = [];
  let listType = null;

  const closeList = () => {
    if (listType) {
      out.push(listType === 'ul' ? '</ul>' : '</ol>');
      listType = null;
    }
  };

  for (const raw of markdown.split('\n')) {
    const line = raw.trimEnd();
    if (!line.trim()) {
      closeList();
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    if (heading) {
      closeList();
      out.push(`<h${heading[1].length}>${inline(heading[2])}</h${heading[1].length}>`);
      continue;
    }
    if (/^[-*]\s+/.test(line)) {
      if (listType !== 'ul') {
        closeList();
        out.push('<ul>');
        listType = 'ul';
      }
      out.push(`<li>${inline(line.replace(/^[-*]\s+/, ''))}</li>`);
      continue;
    }
    if (/^\d+\.\s+/.test(line)) {
      if (listType !== 'ol') {
        closeList();
        out.push('<ol>');
        listType = 'ol';
      }
      out.push(`<li>${inline(line.replace(/^\d+\.\s+/, ''))}</li>`);
      continue;
    }
    if (/^---+$/.test(line)) {
      closeList();
      out.push('<hr />');
      continue;
    }
    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  return out.join('');
}
