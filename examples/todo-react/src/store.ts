// TodoStore — the only module that knows the data lives in Cairn.
//
// It hides every cairn.js implementation detail from the UI: the global
// `cairn` object, schema migration, SQL strings, `?` parameter binding, and
// the rows-as-arrays result shape. The React app talks to this interface
// alone, so swapping the backend (REST, localStorage, tests) means swapping
// this one file.

import type { CairnQueryResult } from './cairn';

export interface Todo {
  id: number;
  title: string;
  done: boolean;
  author: string;
  createdAt: string;
}

export interface StoreInfo {
  /** 'shared' when served by a Cairn server, 'local' during static-file dev. */
  backend: 'shared' | 'local';
  /** Display name of the current user, or null when browsing anonymously. */
  userName: string | null;
  /** Anonymous visitors of public artifacts can read but not write. */
  canWrite: boolean;
}

export interface TodoStore {
  ready(): Promise<StoreInfo>;
  list(): Promise<Todo[]>;
  add(title: string): Promise<void>;
  setDone(id: number, done: boolean): Promise<void>;
  remove(id: number): Promise<void>;
}

function toTodo(row: unknown[]): Todo {
  const [id, title, done, author, createdAt] = row as [number, string, number, string, string];
  return { id, title, done: done !== 0, author, createdAt };
}

class CairnTodoStore implements TodoStore {
  private userName: string | null = null;

  async ready(): Promise<StoreInfo> {
    await cairn.ready();
    const me = await cairn.me();
    this.userName = me ? me.name : null;
    await cairn.db.migrate('001-todos', [{
      sql: 'CREATE TABLE todos (' +
        'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
        'title TEXT NOT NULL, ' +
        'done INTEGER NOT NULL DEFAULT 0, ' +
        'author TEXT NOT NULL, ' +
        'created_at TEXT NOT NULL)',
    }]);
    return {
      backend: cairn.mode === 'remote' ? 'shared' : 'local',
      userName: this.userName,
      canWrite: cairn.mode === 'debug' || this.userName !== null,
    };
  }

  async list(): Promise<Todo[]> {
    const res: CairnQueryResult = await cairn.db.query(
      'SELECT id, title, done, author, created_at FROM todos ORDER BY done, id DESC');
    return res.rows.map(toTodo);
  }

  async add(title: string): Promise<void> {
    await cairn.db.query(
      'INSERT INTO todos (title, author, created_at) VALUES (?, ?, ?)',
      [title, this.userName ?? 'anonymous', new Date().toISOString()]);
  }

  async setDone(id: number, done: boolean): Promise<void> {
    await cairn.db.query('UPDATE todos SET done = ? WHERE id = ?', [done ? 1 : 0, id]);
  }

  async remove(id: number): Promise<void> {
    await cairn.db.query('DELETE FROM todos WHERE id = ?', [id]);
  }
}

export function createStore(): TodoStore {
  return new CairnTodoStore();
}
