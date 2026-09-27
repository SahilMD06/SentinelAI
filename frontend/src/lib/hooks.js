import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Data-fetching hook with a request-generation guard: a slow response from an
 * abandoned filter can never overwrite a newer one.
 */
export function useAsync(fn, deps = [], { immediate = true } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(immediate);
  const generation = useRef(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (...args) => {
    generation.current += 1;
    const current = generation.current;
    setLoading(true);
    setError(null);
    try {
      const result = await fn(...args);
      if (mounted.current && current === generation.current) {
        setData(result);
        setError(null);
      }
      return result;
    } catch (err) {
      if (mounted.current && current === generation.current) setError(err);
      return undefined;
    } finally {
      if (mounted.current && current === generation.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    if (immediate) run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, refresh: run, setData };
}

/** Debounce a rapidly-changing value (search boxes, filter inputs). */
export function useDebounced(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

/** Run a callback on an interval, pausing while the tab is hidden. */
export function useInterval(callback, delayMs, enabled = true) {
  const saved = useRef(callback);
  useEffect(() => {
    saved.current = callback;
  }, [callback]);

  useEffect(() => {
    if (!enabled || !delayMs) return undefined;
    let timer = null;
    const tick = () => {
      if (!document.hidden) saved.current();
    };
    timer = setInterval(tick, delayMs);
    const onVisibility = () => {
      if (!document.hidden) saved.current();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [delayMs, enabled]);
}

/** Persist a small piece of UI state (a filter, a tab) across reloads. */
export function useLocalState(key, initial) {
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored === null ? initial : JSON.parse(stored);
    } catch {
      return initial;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* storage unavailable — state simply stays in memory */
    }
  }, [key, value]);

  return [value, setValue];
}
