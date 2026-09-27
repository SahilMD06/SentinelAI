import { cx } from './ui';
import { formatNumber } from '../lib/format';

/**
 * Ingress pipeline health as a flat stage bar: collection → normalisation →
 * rule matching → ML scoring → indexing. Each stage shows real throughput and
 * the proportion of events that made it through, so a drop in coverage is
 * visible as a shorter bar rather than an animation.
 */
export default function PipelineHealth({ pipeline, compact = false }) {
  if (!pipeline) {
    return <div className="h-[72px] skeleton" />;
  }

  const tone =
    pipeline.status === 'healthy'
      ? { dot: 'bg-success', text: 'text-success' }
      : pipeline.status === 'degraded'
        ? { dot: 'bg-medium', text: 'text-medium' }
        : { dot: 'bg-critical', text: 'text-critical' };

  return (
    <div>
      <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
        <div className="flex items-center gap-2">
          <span className={cx('w-1.5 h-1.5 rounded-full', tone.dot)} />
          <span className={cx('text-xs font-medium capitalize', tone.text)}>{pipeline.status}</span>
          <span className="text-2xs text-ink-3">
            lag {pipeline.lag_seconds < 90 ? `${Math.round(pipeline.lag_seconds)}s` : `${Math.round(pipeline.lag_seconds / 60)}m`}
          </span>
        </div>
        <div className="flex items-center gap-3 text-2xs text-ink-3">
          <span className="tnum">{pipeline.ingest_rate_per_min}/min ingress</span>
          <span className="tnum">queue {formatNumber(pipeline.queue_depth)}</span>
          <span className="tnum">dropped {formatNumber(pipeline.dropped_24h)}</span>
        </div>
      </div>

      <div className={cx('grid gap-2', compact ? 'grid-cols-5' : 'grid-cols-2 sm:grid-cols-3 lg:grid-cols-5')}>
        {pipeline.stages.map((stage) => (
          <div key={stage.key} className="min-w-0">
            <div className="flex items-baseline justify-between gap-1.5 mb-1">
              <span className="text-2xs font-medium text-ink truncate">{stage.label}</span>
              <span className="text-2xs tnum text-ink-3 shrink-0">{stage.health}%</span>
            </div>
            <div className="h-[5px] rounded-full bg-line overflow-hidden">
              <div
                className={cx(
                  'h-full rounded-full transition-all duration-500',
                  stage.health >= 90 ? 'bg-success' : stage.health >= 60 ? 'bg-accent' : 'bg-medium',
                )}
                style={{ width: `${Math.min(stage.health, 100)}%` }}
              />
            </div>
            {!compact && (
              <p className="text-2xs text-ink-3 mt-1 leading-tight truncate" title={stage.detail}>
                {formatNumber(stage.throughput)} · {stage.detail}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
