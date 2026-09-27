import { useMemo } from 'react';
import { Empty, cx } from './ui';
import { IconTarget } from './icons';

/**
 * Flat, left-to-right attack-path diagram: origin → vector → techniques →
 * targeted assets → impact. Nodes are laid out in fixed columns by kind and
 * joined with orthogonal elbow connectors — a schematic an analyst can read at
 * a glance and screenshot into a case write-up, not a decorative graph.
 */

const COLUMN_ORDER = ['source', 'vector', 'technique', 'asset', 'impact'];
const COLUMN_TITLE = {
  source: 'Origin',
  vector: 'Entry vector',
  technique: 'Techniques',
  asset: 'Targeted assets',
  impact: 'Impact',
};

const NODE_W = 158;
const NODE_H = 48;
const COL_GAP = 62;
const ROW_GAP = 14;
const PAD_TOP = 26;

const TONE = {
  source: { box: 'fill-critical/10 stroke-critical/60', text: 'fill-critical' },
  vector: { box: 'fill-high/10 stroke-high/60', text: 'fill-high' },
  technique: { box: 'fill-accent/10 stroke-accent/60', text: 'fill-accent' },
  asset: { box: 'fill-low/10 stroke-low/60', text: 'fill-low' },
  impact: { box: 'fill-medium/10 stroke-medium/60', text: 'fill-medium' },
};

function truncateSvg(text, max) {
  if (!text) return '';
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export default function ThreatChain({ chain }) {
  const layout = useMemo(() => {
    if (!chain?.nodes?.length) return null;

    const columns = COLUMN_ORDER.map((kind) => chain.nodes.filter((n) => n.kind === kind)).filter(
      (column) => column.length > 0,
    );
    const rows = Math.max(...columns.map((c) => c.length));
    const height = PAD_TOP + rows * NODE_H + (rows - 1) * ROW_GAP + 12;
    const width = columns.length * NODE_W + (columns.length - 1) * COL_GAP;

    const positioned = new Map();
    columns.forEach((column, columnIndex) => {
      const columnHeight = column.length * NODE_H + (column.length - 1) * ROW_GAP;
      const offset = PAD_TOP + (height - PAD_TOP - 12 - columnHeight) / 2;
      column.forEach((node, rowIndex) => {
        positioned.set(node.id, {
          ...node,
          x: columnIndex * (NODE_W + COL_GAP),
          y: offset + rowIndex * (NODE_H + ROW_GAP),
          columnIndex,
        });
      });
    });

    const edges = (chain.edges || [])
      .map((edge) => {
        const from = positioned.get(edge.source);
        const to = positioned.get(edge.target);
        if (!from || !to) return null;
        const x1 = from.x + NODE_W;
        const y1 = from.y + NODE_H / 2;
        const x2 = to.x;
        const y2 = to.y + NODE_H / 2;
        const mid = x1 + (x2 - x1) / 2;
        return {
          ...edge,
          path: `M${x1},${y1} H${mid} V${y2} H${x2}`,
          labelX: mid,
          labelY: Math.min(y1, y2) + Math.abs(y2 - y1) / 2 - 4,
          straight: Math.abs(y1 - y2) < 1,
        };
      })
      .filter(Boolean);

    return {
      columns,
      nodes: [...positioned.values()],
      edges,
      width,
      height,
      headers: columns.map((column, index) => ({
        label: COLUMN_TITLE[column[0].kind],
        x: index * (NODE_W + COL_GAP),
      })),
    };
  }, [chain]);

  if (!layout) {
    return <Empty icon={IconTarget} title="No threat chain available" hint="Run an investigation to derive the attack path for this case." />;
  }

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        width={layout.width}
        height={layout.height}
        className="max-w-none"
        role="img"
        aria-label="Threat chain diagram"
      >
        <defs>
          <marker id="tc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,1 L9,5 L0,9 z" className="fill-line-strong" />
          </marker>
        </defs>

        {layout.headers.map((header) => (
          <text
            key={header.label}
            x={header.x}
            y={12}
            className="fill-ink-3"
            style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}
          >
            {header.label.toUpperCase()}
          </text>
        ))}

        {layout.edges.map((edge, index) => (
          <g key={index}>
            <path
              d={edge.path}
              fill="none"
              className="stroke-line-strong"
              strokeWidth="1.3"
              markerEnd="url(#tc-arrow)"
            />
            {edge.label && edge.straight && (
              <text
                x={edge.labelX}
                y={edge.labelY}
                textAnchor="middle"
                className="fill-ink-3"
                style={{ fontSize: 8.5 }}
              >
                {truncateSvg(edge.label, 22)}
              </text>
            )}
          </g>
        ))}

        {layout.nodes.map((node) => {
          const tone = TONE[node.kind] || TONE.technique;
          return (
            <g key={node.id}>
              <rect
                x={node.x}
                y={node.y}
                width={NODE_W}
                height={NODE_H}
                rx="4"
                className={cx(tone.box)}
                strokeWidth="1.2"
              />
              <text
                x={node.x + 10}
                y={node.y + 19}
                className={cx(tone.text)}
                style={{ fontSize: 11.5, fontWeight: 600 }}
              >
                {truncateSvg(node.label, 21)}
              </text>
              {node.sublabel && (
                <text
                  x={node.x + 10}
                  y={node.y + 33}
                  className="fill-ink-3"
                  style={{ fontSize: 9.5 }}
                >
                  {truncateSvg(node.sublabel, 25)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
