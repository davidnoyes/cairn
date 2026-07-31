/* Team Poll — a multi-file Cairn artifact.
 *
 * Demonstrates that everything in the version directory is served relative to
 * the version URL: this script, style.css, assets/*.svg, and config.json are
 * all plain files next to index.html. Votes go to the version's shared SQLite
 * database through cairn.js (debug mode: an in-browser SQLite).
 */
(async function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  let config;
  let myVote = null; // option id voted for in this session

  function esc(parent, tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    parent.appendChild(el);
    return el;
  }

  async function refresh() {
    const res = await cairn.db.query(
      'SELECT option_id, COUNT(*) FROM votes GROUP BY option_id');
    const counts = Object.fromEntries(res.rows);
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    $('total').textContent = String(total);

    const box = $('options');
    box.innerHTML = '';
    for (const opt of config.options) {
      const n = counts[opt.id] || 0;
      const pct = total ? Math.round((n / total) * 100) : 0;

      const btn = esc(box, 'button', 'option' + (myVote === opt.id ? ' voted' : ''));
      btn.type = 'button';
      const bar = esc(btn, 'span', 'bar');
      bar.style.width = pct + '%';
      const row = esc(btn, 'span', 'row');
      const check = document.createElement('img');
      check.src = './assets/check.svg';
      check.alt = '';
      row.appendChild(check);
      esc(row, 'span', 'label', opt.label);
      esc(row, 'span', 'count', n + ' · ' + pct + '%');

      btn.addEventListener('click', () => vote(opt.id));
    }
  }

  async function vote(optionId) {
    const me = await cairn.me();
    await cairn.db.query(
      'INSERT INTO votes (option_id, voter, created_at) VALUES (?, ?, ?)',
      [optionId, me ? me.name : 'anonymous', new Date().toISOString()]);
    myVote = optionId;
    await refresh();
  }

  try {
    // Relative fetch works because a version is always served under its own
    // directory URL.
    config = await (await fetch('./config.json')).json();
    $('question').textContent = config.question;
    document.title = config.question;

    await cairn.ready();
    $('mode').textContent = cairn.mode;
    const me = await cairn.me();
    $('who').textContent = me ? me.name : 'anonymous (read-only)';

    await cairn.db.migrate('001-votes', [{
      sql: 'CREATE TABLE votes (id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
           'option_id TEXT NOT NULL, voter TEXT, created_at TEXT NOT NULL)',
    }]);

    await refresh();
    setInterval(() => refresh().catch(() => {}), 5000);
  } catch (err) {
    $('options').innerHTML = '';
    esc($('options'), 'p', 'error', 'Could not start: ' + err.message);
  }
})();
