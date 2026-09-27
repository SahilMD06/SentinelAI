import { useEffect, useRef, useState } from 'react';
import {
  Button,
  Chip,
  Empty,
  Loading,
  LockedNotice,
  Panel,
  Spinner,
  cx,
  useToast,
} from '../components/ui';
import { IconBook, IconRefresh, IconSearch, IconSend, IconSpark } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { formatDuration, formatNumber, relativeTime, renderMarkdown } from '../lib/format';

const SESSION_KEY = 'default';

export default function Copilot() {
  const { can } = useAuth();
  const toast = useToast();
  const allowed = can('copilot:chat');

  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupResults, setLookupResults] = useState(null);
  const [lookupBusy, setLookupBusy] = useState(false);
  const listRef = useRef(null);

  const history = useAsync(() => api.copilotHistory(SESSION_KEY), []);
  const status = useAsync(() => api.ragStatus(), []);

  useEffect(() => {
    if (history.data?.messages) setMessages(history.data.messages);
  }, [history.data]);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages, sending]);

  const send = async (text) => {
    const message = (text ?? input).trim();
    if (!message || sending) return;
    setInput('');
    setMessages((list) => [...list, { role: 'user', content: message, created_at: null }]);
    setSending(true);
    try {
      const reply = await api.copilot(message, SESSION_KEY);
      setMessages((list) => [
        ...list,
        {
          role: 'assistant',
          content: reply.reply,
          citations: reply.citations,
          latency_ms: reply.latency_ms,
          created_at: null,
        },
      ]);
    } catch (err) {
      toast.error(err.message);
      setMessages((list) => list.slice(0, -1));
      setInput(message);
    } finally {
      setSending(false);
    }
  };

  const runLookup = async () => {
    if (!lookupQuery.trim()) return;
    setLookupBusy(true);
    try {
      const hits = await api.ragSearch(lookupQuery.trim(), 8);
      setLookupResults(hits);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setLookupBusy(false);
    }
  };

  const suggested = history.data?.suggested || [];

  return (
    <div className="p-4 h-full grid lg:grid-cols-[1fr_300px] gap-4 min-h-0">
      <Panel className="min-h-0" bodyClass="p-0 h-full flex flex-col" dense>
        <div ref={listRef} className="flex-1 overflow-y-auto scroll-y px-4 py-4 space-y-4">
          {history.loading && !history.data ? (
            <Loading className="py-16" />
          ) : messages.length === 0 ? (
            <Empty
              icon={IconSpark}
              title="Ask Security Copilot"
              hint="Grounded answers over the knowledge base and live case/telemetry data — every claim is cited or backed by a query."
              className="py-16"
            />
          ) : (
            messages.map((message, index) => (
              <ChatBubble key={index} message={message} />
            ))
          )}
          {sending && (
            <div className="flex items-center gap-2 text-xs text-ink-3 pl-1">
              <Spinner /> Composing a grounded answer…
            </div>
          )}
        </div>

        <div className="border-t border-line p-3 shrink-0">
          {!allowed ? (
            <LockedNotice>
              Your role does not include Copilot access. Ask an administrator for the Security
              Analyst or SOC Manager role.
            </LockedNotice>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                send();
              }}
              className="flex items-end gap-2"
            >
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
                rows={1}
                placeholder="Ask about a case, an ATT&CK technique, an IP, or response guidance… (Enter to send)"
                className="field resize-none py-2 max-h-28"
              />
              <Button type="submit" variant="primary" disabled={sending || !input.trim()}>
                <IconSend size={14} /> Send
              </Button>
            </form>
          )}
        </div>
      </Panel>

      <div className="space-y-4 min-h-0 overflow-auto">
        <Panel title="Suggested prompts" dense bodyClass="p-2">
          {suggested.length ? (
            <div className="flex flex-col gap-1">
              {suggested.map((prompt) => (
                <button
                  key={prompt}
                  type="button"
                  disabled={!allowed}
                  onClick={() => send(prompt)}
                  className={cx(
                    'text-left text-xs text-ink-2 rounded px-2.5 py-2 leading-snug',
                    'hover:bg-sunken hover:text-ink transition-colors duration-120',
                    !allowed && 'opacity-50 cursor-not-allowed',
                  )}
                >
                  {prompt}
                </button>
              ))}
            </div>
          ) : (
            <p className="text-2xs text-ink-3 p-2">No suggestions available.</p>
          )}
        </Panel>

        <Panel title="Knowledge base" dense bodyClass="p-3 space-y-2">
          <div className="flex items-center justify-between text-2xs text-ink-3">
            <span>
              {status.data ? `${formatNumber(status.data.documents)} documents` : '—'} ·{' '}
              {status.data?.vector_backend || 'tf-idf'}
            </span>
            <span className={cx('inline-flex items-center gap-1')}>
              <span className={cx('w-1.5 h-1.5 rounded-full', status.data && !status.data.embedding_backend?.startsWith('hashing') ? 'bg-success' : 'bg-medium')} />
              {status.data && !status.data.embedding_backend?.startsWith('hashing') ? 'live embeddings' : 'offline'}
            </span>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              runLookup();
            }}
            className="flex items-center gap-1.5"
          >
            <div className="relative flex-1">
              <IconSearch size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-ink-3" />
              <input
                value={lookupQuery}
                onChange={(e) => setLookupQuery(e.target.value)}
                placeholder="Search playbooks / MITRE…"
                className="field h-7 pl-6 text-2xs"
              />
            </div>
            <Button size="sm" type="submit" disabled={lookupBusy || !lookupQuery.trim()}>
              {lookupBusy ? <Spinner size={12} /> : <IconRefresh size={12} />}
            </Button>
          </form>
          {lookupResults && (
            <ul className="space-y-1.5 max-h-56 overflow-y-auto scroll-y">
              {lookupResults.length ? (
                lookupResults.map((hit) => (
                  <li key={hit.doc_key} className="rounded border border-line px-2 py-1.5">
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="text-2xs font-medium text-ink truncate">{hit.title}</span>
                      <span className="text-2xs tnum text-ink-3 shrink-0">{hit.score.toFixed(2)}</span>
                    </div>
                    <p className="text-2xs text-ink-3 mt-0.5 line-clamp-2" style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                      {hit.snippet}
                    </p>
                  </li>
                ))
              ) : (
                <li className="text-2xs text-ink-3 px-1">No matches.</li>
              )}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function ChatBubble({ message }) {
  const isUser = message.role === 'user';
  return (
    <div className={cx('flex', isUser ? 'justify-end' : 'justify-start')}>
      <div className={cx('max-w-[85%] rounded-lg px-3.5 py-2.5', isUser ? 'bg-accent/10 border border-accent/25' : 'bg-sunken border border-line')}>
        {isUser ? (
          <p className="text-sm text-ink whitespace-pre-wrap leading-relaxed">{message.content}</p>
        ) : (
          <div
            className="md text-sm"
            dangerouslySetInnerHTML={{ __html: renderMarkdown(message.content) }}
          />
        )}
        {!isUser && message.citations?.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t border-line/70">
            <span className="text-2xs text-ink-3 flex items-center gap-1 mr-1">
              <IconBook size={11} /> Sources:
            </span>
            {message.citations.map((c) => (
              <Chip key={c.doc_key}>{c.title}</Chip>
            ))}
          </div>
        )}
        <div className="flex items-center gap-2 mt-1.5">
          {message.created_at && (
            <span className="text-2xs text-ink-3">{relativeTime(message.created_at)}</span>
          )}
          {message.latency_ms !== undefined && (
            <span className="text-2xs text-ink-3">{formatDuration(message.latency_ms)}</span>
          )}
        </div>
      </div>
    </div>
  );
}
