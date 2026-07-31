# Team Poll

A multi-file Cairn artifact: `index.html`, `app.js`, `style.css`, `config.json`,
and `assets/*.svg` are plain files served relative to the version URL. Votes are
rows in the version's shared SQLite database — everyone who opens the artifact
sees the same tally.

Edit `config.json` to change the question and options (re-push to publish; the
votes table survives re-uploads).

```sh
# develop locally — cairn.js falls back to an in-browser SQLite
python3 -m http.server -d examples/poll   # then open http://localhost:8000

# publish
cairn push examples/poll --artifact poll --create --public
```
