# Drive

A shared file drive built entirely on the per-version **file storage**
(`cairn.files`) — no database at all. Everyone who opens the artifact sees the
same files: upload via picker or drag-and-drop, browse folders, download,
delete. Anonymous visitors of a public artifact get a read-only view.

Folders are implicit: a "folder" exists because file paths contain slashes
(`photos/cat.png`), exactly how the storage API works. Image files get inline
thumbnails — served straight from `cairn.files.url(path)` on a Cairn server,
or through `download()` + an object URL in local debug mode (where files
persist to the browser's IndexedDB instead).

```sh
# develop locally — cairn.js keeps files in the browser (IndexedDB)
python3 -m http.server -d examples/drive   # then open http://localhost:8000

# publish
cairn push examples/drive --artifact drive --create --public

# the same storage is scriptable from the CLI
cairn files put ./notes.pdf --artifact drive --path docs/notes.pdf
cairn files list --artifact drive
```
