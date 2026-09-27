import { useState } from 'react';
import { Button, CopyButton, Empty, cx } from './ui';
import { IconBook, IconChevron, IconLink, IconSpark } from './icons';
import { formatDuration, formatNumber, formatTime, renderMarkdown } from '../lib/format';

/**
 * The agent workspace: an audit surface, not a chat log. Each row exposes what
 * the agent concluded, the reasoning that produced it, which knowledge-base
 * documents it cited, which tools it called, and what it cost — because a
 * conclusion an analyst cannot interrogate is a conclusion they cannot use.
 */

const AGENT_ORDER_LABEL = (position) => String(position + 1).padStart(2, '0');

function StepRow({ step, expanded, onToggle, isLast }) {
  const failed = step.status !== 'completed';
  const confidenceTone =
    step.confidence >= 80 ? 'text-success' : step.confidence >= 55 ? 'text-medium' : 'text-critical';

  return (
    <li className="relative pl-8">
      {/* Rail */}
      {!isLast && <span className="absolute left-[11px] top-6 bottom-0 w-px bg-line" />}
      <span
        className={cx(
          'absolute left-[3px] top-[7px] w-[17px] h-[17px] rounded-full border-2 flex items-center justify-center',
          failed ? 'border-critical bg-critical/15' : 'border-accent bg-surface',
        )}
      >
        <span className={cx('w-[5px] h-[5px] rounded-full', failed ? 'bg-critical' : 'bg-accent')} />
      </span>

      <div className={cx('pb-4', expanded && 'pb-5')}>
        <button
          type="button"
          onClick={onToggle}
          className="w-full text-left group"
          aria-expanded={expanded}
        >
          <div className="flex items-start gap-2">
            <span className="text-2xs tnum text-ink-3 mt-[3px] shrink-0">
              {AGENT_ORDER_LABEL(step.position)}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-semibold text-ink group-hover:text-accent transition-colors duration-120">
                  {step.agent_name}
                </span>
                {failed && <span className="badge bg-critical/12 text-critical border border-critical/30">failed</span>}
                <span className="text-2xs tnum text-ink-3">
                  {formatDuration(step.latency_ms)} · {formatNumber(step.tokens_in + step.tokens_out)} tok
                </span>
                <span className={cx('text-2xs tnum', confidenceTone)}>{step.confidence}% conf</span>
              </div>
              <p className="text-sm text-ink-2 mt-0.5 leading-snug">{step.headline}</p>
            </div>
            <IconChevron
              size={14}
              className={cx(
                'text-ink-3 shrink-0 mt-1 transition-transform duration-120',
                expanded && 'rotate-90',
              )}
            />
          </div>
        </button>

        {expanded && (
          <div className="mt-2.5 space-y-3 animate-fade-in">
            <div className="rounded border border-line bg-sunken p-3">
              <p className="section-label mb-1.5">Reasoning trace</p>
              <pre className="font-mono text-xs text-ink-2 whitespace-pre-wrap leading-relaxed">
                {step.reasoning}
              </pre>
            </div>

            {step.rag_sources?.length > 0 && (
              <div>
                <p className="section-label mb-1.5 flex items-center gap-1.5">
                  <IconBook size={12} /> Knowledge retrieved ({step.rag_sources.length})
                </p>
                <ul className="space-y-1">
                  {step.rag_sources.map((source) => (
                    <li
                      key={source.doc_key}
                      className="flex items-start gap-2 text-xs rounded border border-line px-2.5 py-1.5"
                    >
                      <span className="text-2xs font-mono text-ink-3 shrink-0 mt-px">
                        {source.score?.toFixed(3)}
                      </span>
                      <span className="min-w-0">
                        <span className="block text-ink font-medium truncate">{source.title}</span>
                        <span className="block text-ink-3 leading-relaxed mt-0.5">{source.snippet}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {step.tool_calls?.length > 0 && (
              <div>
                <p className="section-label mb-1.5 flex items-center gap-1.5">
                  <IconLink size={12} /> Tool calls ({step.tool_calls.length})
                </p>
                <div className="rounded border border-line overflow-hidden">
                  {step.tool_calls.map((call, index) => (
                    <div
                      key={index}
                      className="flex items-start gap-2 px-2.5 py-1.5 border-b border-line last:border-0 font-mono text-2xs"
                    >
                      <span className="text-accent shrink-0">{call.tool}</span>
                      <span className="text-ink-3 min-w-0 break-all">
                        {JSON.stringify(call.args ?? {})}
                        {call.result !== undefined && ` → ${JSON.stringify(call.result)}`}
                        {call.result_count !== undefined && ` → ${call.result_count} result(s)`}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {step.findings?.markdown ? (
              <div className="rounded border border-line p-3">
                <p className="section-label mb-1.5">Rendered output</p>
                <div
                  className="md"
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(step.findings.markdown) }}
                />
              </div>
            ) : (
              step.findings &&
              Object.keys(step.findings).length > 0 && (
                <details className="rounded border border-line">
                  <summary className="cursor-pointer px-2.5 py-1.5 text-2xs text-ink-3 hover:text-ink select-none">
                    Structured findings (JSON)
                  </summary>
                  <pre className="px-2.5 pb-2.5 font-mono text-2xs text-ink-2 whitespace-pre-wrap break-all">
                    {JSON.stringify(step.findings, null, 2)}
                  </pre>
                </details>
              )
            )}
          </div>
        )}
      </div>
    </li>
  );
}

export default function AgentTimeline({ runs = [], onInvestigate, canRun, running }) {
  const [runIndex, setRunIndex] = useState(0);
  const [expanded, setExpanded] = useState(() => new Set([0]));

  if (!runs.length) {
    return (
      <Empty
        icon={IconSpark}
        title="No investigation has run on this case"
        hint="The nine-agent pipeline analyses the correlated telemetry, enriches it with external reputation and the knowledge base, then writes back a risk index, ATT&CK mapping, root cause and playbook."
        action={
          <Button
            variant="primary"
            icon={IconSpark}
            onClick={onInvestigate}
            locked={!canRun}
            lockedReason="Running agents requires Analyst, SOC Manager or Administrator"
            disabled={running}
          >
            {running ? 'Running…' : 'Run investigation'}
          </Button>
        }
      />
    );
  }

  const run = runs[runIndex];
  const toggle = (position) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(position)) next.delete(position);
      else next.add(position);
      return next;
    });

  return (
    <div className="flex flex-col min-h-0">
      <div className="flex items-center justify-between gap-3 flex-wrap px-4 py-2.5 border-b border-line bg-sunken/60">
        <div className="flex items-center gap-2 flex-wrap text-2xs text-ink-3">
          <span className="font-mono text-ink-2">trace {run.trace_id.slice(0, 12)}</span>
          <CopyButton value={run.trace_id} label="copy" />
          <span>·</span>
          <span>{formatTime(run.started_at)}</span>
          <span>·</span>
          <span>{formatDuration(run.duration_ms)}</span>
          <span>·</span>
          <span className="tnum">{formatNumber(run.tokens_in + run.tokens_out)} tokens</span>
          <span>·</span>
          <span className="tnum">${run.cost_usd?.toFixed(4)}</span>
          <span>·</span>
          <span>{run.trigger_reason}</span>
        </div>
        <div className="flex items-center gap-1.5">
          {runs.length > 1 && (
            <select
              className="field h-7 text-xs w-auto"
              value={runIndex}
              onChange={(event) => setRunIndex(Number(event.target.value))}
              aria-label="Select investigation run"
            >
              {runs.map((item, index) => (
                <option key={item.id} value={index}>
                  Run {runs.length - index} · {formatTime(item.started_at)}
                </option>
              ))}
            </select>
          )}
          <Button
            size="sm"
            variant="primary"
            icon={IconSpark}
            onClick={onInvestigate}
            locked={!canRun}
            lockedReason="Running agents requires Analyst, SOC Manager or Administrator"
            disabled={running}
          >
            {running ? 'Running…' : 'Re-run'}
          </Button>
        </div>
      </div>

      <div className="scroll-y px-4 pt-4 min-h-0">
        <ol className="relative">
          {run.steps.map((step, index) => (
            <StepRow
              key={step.id}
              step={step}
              expanded={expanded.has(step.position)}
              onToggle={() => toggle(step.position)}
              isLast={index === run.steps.length - 1}
            />
          ))}
        </ol>
      </div>
    </div>
  );
}
