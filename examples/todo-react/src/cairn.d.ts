// Type declarations for the cairn.js client library, which the page loads with
// <script src="./cairn.js"></script> before the bundle runs. Only store.ts
// should touch this global — the rest of the app goes through the TodoStore.

export interface CairnUser {
  id: number;
  name: string;
  email?: string;
  isAdmin?: boolean;
}

export interface CairnQueryResult {
  columns: string[];
  types: string[];
  /** Rows come back as arrays in column order, not objects. */
  rows: unknown[][];
  rowsAffected: number;
  lastInsertId: number;
}

export interface CairnStatement {
  sql: string;
  params?: unknown[];
}

export interface CairnDb {
  query(sql: string, params?: unknown[], opts?: { version?: string }): Promise<CairnQueryResult>;
  batch(statements: CairnStatement[]): Promise<CairnQueryResult[]>;
  /** Run-once, concurrency-safe migration; resolves true if this client applied it. */
  migrate(name: string, statements: CairnStatement[]): Promise<boolean>;
  downloadURL: string | null;
}

export interface Cairn {
  mode: 'remote' | 'debug';
  artifactId: string;
  versionId: string;
  ready(): Promise<void>;
  me(): Promise<CairnUser | null>;
  users(): Promise<CairnUser[]>;
  login(): void;
  db: CairnDb;
}

declare global {
  var cairn: Cairn;
}
