import { useCallback, useEffect, useRef, useState } from 'react';
import type { StoreInfo, Todo, TodoStore } from './store';

export function App({ store }: { store: TodoStore }) {
  const [info, setInfo] = useState<StoreInfo | null>(null);
  const [todos, setTodos] = useState<Todo[]>([]);
  const [title, setTitle] = useState('');
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);

  const refresh = useCallback(async () => {
    setTodos(await store.list());
  }, [store]);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    store
      .ready()
      .then(async (i) => {
        setInfo(i);
        await refresh();
        // Other people write to the same database — poll for their changes.
        timer = setInterval(() => refresh().catch(() => {}), 5000);
      })
      .catch((err: Error) => setError(err.message));
    return () => clearInterval(timer);
  }, [store, refresh]);

  async function run(action: () => Promise<void>) {
    if (busy.current) return;
    busy.current = true;
    try {
      setError(null);
      await action();
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      busy.current = false;
    }
  }

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const t = title.trim();
    if (!t) return;
    setTitle('');
    void run(() => store.add(t));
  };

  if (error && !info) return <p className="error">Could not start: {error}</p>;
  if (!info) return <p className="dim">Loading…</p>;

  const open = todos.filter((t) => !t.done).length;

  return (
    <>
      <header>
        <h1>Shared Todos</h1>
        <p className="meta">
          {info.backend === 'shared' ? 'shared list' : 'local dev list'}
          {' · '}
          {info.userName ?? 'anonymous (read-only)'}
          {' · '}
          {open} open
        </p>
      </header>

      {info.canWrite && (
        <form onSubmit={onSubmit}>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Add a todo…"
            maxLength={200}
            aria-label="New todo"
          />
          <button type="submit">Add</button>
        </form>
      )}

      {error && <p className="error">{error}</p>}

      <ul>
        {todos.map((t) => (
          <li key={t.id} className={t.done ? 'done' : ''}>
            <label>
              <input
                type="checkbox"
                checked={t.done}
                disabled={!info.canWrite}
                onChange={(e) => void run(() => store.setDone(t.id, e.target.checked))}
              />
              <span className="title">{t.title}</span>
            </label>
            <span className="who">{t.author}</span>
            {info.canWrite && (
              <button
                type="button"
                className="del"
                aria-label={`Delete "${t.title}"`}
                onClick={() => void run(() => store.remove(t.id))}
              >
                ×
              </button>
            )}
          </li>
        ))}
        {todos.length === 0 && <p className="dim">Nothing yet — add the first todo.</p>}
      </ul>
    </>
  );
}
