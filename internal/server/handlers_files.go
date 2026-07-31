package server

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fileInfo is the JSON shape of one stored file.
type fileInfo struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modifiedAt"`
}

func fileModTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// filePathParam validates the {path...} segment of file routes: a clean,
// relative, slash-separated path (the mux normalizes literal "..", but
// percent-encoded dots arrive intact, so fs.ValidPath is load-bearing).
func filePathParam(r *http.Request) (string, bool) {
	p := r.PathValue("path")
	if p == "" || p == "." || !fs.ValidPath(p) || strings.Contains(p, `\`) {
		return "", false
	}
	return p, true
}

// resolveVersionFile validates the version and file path, returning the
// version's file storage root and the target's absolute path.
func (s *Server) resolveVersionFile(w http.ResponseWriter, r *http.Request) (root, target string, ok bool) {
	aid, ok := s.resolveVersion(w, r)
	if !ok {
		return "", "", false
	}
	rel, ok := filePathParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid file path")
		return "", "", false
	}
	root = s.layout.VersionFilesDir(aid, r.PathValue("vid"))
	return root, filepath.Join(root, filepath.FromSlash(rel)), true
}

// handleFileList returns every stored file of a version; a version that was
// never written to lists as empty.
func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	aid, ok := s.resolveVersion(w, r)
	if !ok {
		return
	}
	root := s.layout.VersionFilesDir(aid, r.PathValue("vid"))
	files := []fileInfo{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, fileInfo{
			Path:       filepath.ToSlash(rel),
			Size:       info.Size(),
			ModifiedAt: fileModTime(info.ModTime()),
		})
		return nil
	})
	if err != nil {
		s.log.Error("list files", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, paginate(r, files))
}

// handleFileDownload streams one stored file (range requests supported, type
// derived from the extension).
func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	_, target, ok := s.resolveVersionFile(w, r)
	if !ok {
		return
	}
	f, err := os.Open(target)
	if err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	http.ServeContent(w, r, filepath.Base(target), st.ModTime(), f)
}

// handleFileUpload stores the raw request body at the given path, overwriting
// any previous content. The file is staged in tmp/ and renamed into place
// (same volume) so concurrent readers never see a partial write.
func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	_, target, ok := s.resolveVersionFile(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes())
	tmp, err := os.CreateTemp(s.layout.TmpRoot(), "file-*")
	if err != nil {
		s.log.Error("stage file upload", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, r.Body)
	tmp.Close()
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "file exceeds the maximum upload size")
			return
		}
		s.log.Error("receive file upload", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to receive file")
		return
	}
	os.Chmod(tmp.Name(), 0o644)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		writeError(w, http.StatusConflict, "path conflicts with an existing file")
		return
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		writeError(w, http.StatusConflict, "path conflicts with an existing directory")
		return
	}
	writeJSON(w, http.StatusOK, fileInfo{
		Path:       r.PathValue("path"),
		Size:       n,
		ModifiedAt: fileModTime(time.Now()),
	})
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	root, target, ok := s.resolveVersionFile(w, r)
	if !ok {
		return
	}
	st, err := os.Lstat(target)
	if err != nil || st.IsDir() {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	if err := os.Remove(target); err != nil {
		s.log.Error("delete file", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Prune now-empty parent directories (they are invisible to the API).
	for dir := filepath.Dir(target); len(dir) > len(root); dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
