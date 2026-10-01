package server

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// maxCompressedFactor bounds the total decompressed size relative to the
// configured cap; individual entry claims are also verified while copying so a
// lying zip header cannot bypass the limit.
func (s *Server) maxUploadBytes() int64 { return s.cfg.MaxUploadMB << 20 }

var errNoIndex = errors.New("archive must contain an index.html at its root (or inside a single top-level directory)")

// handleUploadVersion creates a new version from a multipart zip upload.
// Form fields: archive (file, required), name, changelog.
func (s *Server) handleUploadVersion(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	contentDir, name, changelog, ok := s.receiveUpload(w, r, a.ID)
	if !ok {
		return
	}
	v, err := s.store.CreateVersion(a.ID, name, changelog, contentDir)
	if err != nil {
		os.RemoveAll(s.layout.ContentDir(a.ID, contentDir))
		s.writeStoreError(w, err, "version")
		return
	}
	s.recordPusher(a.ID, v.ID, requestUser(r).ID)
	if pushed, err := s.store.VersionByID(a.ID, v.ID); err == nil {
		v = pushed
	}
	s.log.Info("version uploaded", "artifact", a.ID, "version", v.ID, "seq", v.Seq, "by", requestUser(r).Email)
	writeJSON(w, http.StatusCreated, v)
}

// handleReplaceVersion re-uploads an existing version's content (allowed by
// design: Cairn trusts its users; iterating agents overwrite work-in-progress
// versions). The version's shared database is untouched.
func (s *Server) handleReplaceVersion(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	v, err := s.store.VersionByID(a.ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	contentDir, name, changelog, ok := s.receiveUpload(w, r, a.ID)
	if !ok {
		return
	}
	if name == "" {
		name = v.Name
	}
	if changelog == "" {
		changelog = v.Changelog
	}
	prev, err := s.store.SwapVersionContent(v.ArtifactID, v.ID, contentDir, name, changelog)
	if err != nil {
		os.RemoveAll(s.layout.ContentDir(v.ArtifactID, contentDir))
		s.writeStoreError(w, err, "version")
		return
	}
	// Open file handles on the old dir keep serving until closed (POSIX);
	// new requests resolve the new pointer.
	os.RemoveAll(s.layout.ContentDir(v.ArtifactID, prev))
	s.recordPusher(v.ArtifactID, v.ID, requestUser(r).ID)
	v, _ = s.store.VersionByID(v.ArtifactID, v.ID)
	s.log.Info("version replaced", "artifact", v.ArtifactID, "version", v.ID, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, v)
}

// receiveUpload parses the multipart request and extracts the archive into a
// fresh content dir, reporting errors to the client itself.
func (s *Server) receiveUpload(w http.ResponseWriter, r *http.Request, artifactID string) (contentDir, name, changelog string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes())
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	name = r.FormValue("name")
	changelog = r.FormValue("changelog")
	file, _, err := r.FormFile("archive")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'archive' zip file field")
		return
	}
	defer file.Close()

	contentDir = uuid.NewString()
	dest := s.layout.ContentDir(artifactID, contentDir)
	if err := s.extractZip(file, dest); err != nil {
		os.RemoveAll(dest)
		status := http.StatusBadRequest
		if !errors.Is(err, errNoIndex) && !errors.Is(err, errZipEntry) {
			status = http.StatusInternalServerError
			s.log.Error("extract upload", "err", err)
			err = errors.New("failed to extract archive")
		}
		writeError(w, status, err.Error())
		return "", "", "", false
	}
	return contentDir, name, changelog, true
}

var errZipEntry = errors.New("invalid zip entry")

// extractZip safely extracts an uploaded zip into dest:
//   - entry names must be clean, relative, slash-separated paths
//   - only regular files and directories (no symlinks)
//   - decompressed bytes are counted against the configured cap
//   - a single wrapping top-level directory is stripped
//   - index.html must exist at the (effective) root
func (s *Server) extractZip(file io.ReaderAt, dest string) error {
	size, err := readerSize(file)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(file, size)
	if err != nil {
		return fmt.Errorf("%w: not a valid zip archive", errZipEntry)
	}

	prefix := commonRootDir(zr)
	hasIndex := false
	var total int64
	budget := s.maxUploadBytes()
	for _, f := range zr.File {
		entryName := strings.TrimPrefix(f.Name, prefix)
		if entryName == "" {
			continue
		}
		isDir := strings.HasSuffix(entryName, "/")
		entryName = strings.TrimSuffix(entryName, "/")
		if !fs.ValidPath(entryName) || strings.Contains(entryName, `\`) {
			return fmt.Errorf("%w: unsafe path %q", errZipEntry, f.Name)
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (!isDir && !mode.IsRegular()) {
			return fmt.Errorf("%w: %q is not a regular file", errZipEntry, f.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(entryName))
		if isDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if entryName == "index.html" {
			hasIndex = true
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		n, err := copyCapped(target, rc, budget-total)
		rc.Close()
		if err != nil {
			return err
		}
		total += n
	}
	if !hasIndex {
		return errNoIndex
	}
	return nil
}

// commonRootDir returns "dir/" when every entry lives under a single
// top-level directory (the usual result of zipping a folder), else "".
func commonRootDir(zr *zip.Reader) string {
	root := ""
	for _, f := range zr.File {
		name := strings.TrimSuffix(f.Name, "/")
		top, rest, found := strings.Cut(name, "/")
		if !found {
			if !f.FileInfo().IsDir() {
				return "" // file at root
			}
			continue
		}
		_ = rest
		if root == "" {
			root = top
		} else if top != root {
			return ""
		}
	}
	if root == "" {
		return ""
	}
	return root + "/"
}

func copyCapped(target string, r io.Reader, budget int64) (int64, error) {
	if budget <= 0 {
		return 0, fmt.Errorf("%w: archive exceeds the maximum decompressed size", errZipEntry)
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(r, budget+1))
	if err != nil {
		return n, err
	}
	if n > budget {
		return n, fmt.Errorf("%w: archive exceeds the maximum decompressed size", errZipEntry)
	}
	return n, nil
}

func readerSize(r io.ReaderAt) (int64, error) {
	switch f := r.(type) {
	case interface{ Size() int64 }:
		return f.Size(), nil
	case *os.File:
		st, err := f.Stat()
		if err != nil {
			return 0, err
		}
		return st.Size(), nil
	default:
		// Seek to the end to measure.
		if s, ok := r.(io.Seeker); ok {
			return s.Seek(0, io.SeekEnd)
		}
		return 0, errors.New("cannot determine upload size")
	}
}

// serveFileFromVersion is defined in serving.go (M4); path helper shared here.
func cleanRequestPath(p string) (string, bool) {
	p = path.Clean("/" + p)
	if strings.Contains(p, "..") {
		return "", false
	}
	return strings.TrimPrefix(p, "/"), true
}
