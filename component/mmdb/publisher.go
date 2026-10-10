package mmdb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/ProjectClash/Clash/log"

	"github.com/oschwald/maxminddb-golang"
)


type snapshot struct {
	reader       *maxminddb.Reader
	databaseType databaseType
	refs         int
	retired      bool
	closed       bool
	close        func()

	countsOnce sync.Once
	counts     map[string]int
}

type readerHolder struct {
	mu      sync.Mutex
	current *snapshot
}

func (h *readerHolder) acquire() *snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.current
	if s != nil {
		s.refs++
	}
	return s
}

func (h *readerHolder) release(s *snapshot) {
	if s == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s.refs--
	if s.retired && s.refs == 0 && !s.closed {
		s.closed = true
		s.close()
	}
}

func (h *readerHolder) publish(reader *maxminddb.Reader) {
	next := &snapshot{reader: reader, databaseType: databaseTypeOf(reader), close: func() { _ = reader.Close() }}
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.current
	h.current = next
	if old != nil {
		old.retired = true
		if old.refs == 0 && !old.closed {
			old.closed = true
			old.close()
		}
	}
}

func (h *readerHolder) available() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current != nil
}

type tempFile interface {
	Name() string
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

type fileOps interface {
	CreateTemp(dir, pattern string) (tempFile, error)
	Open(path string) (*maxminddb.Reader, error)
	FromBytes(data []byte) (*maxminddb.Reader, error)
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
	Rename(oldPath, newPath string) error
	SyncDir(dir string) error
	Remove(path string) error
}

type osFileOps struct{}

func (osFileOps) CreateTemp(dir, pattern string) (tempFile, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.CreateTemp(dir, pattern)
}

func (osFileOps) Open(path string) (*maxminddb.Reader, error) {
	return openDatabaseFile(path)
}

func (osFileOps) FromBytes(data []byte) (*maxminddb.Reader, error) { return maxminddb.FromBytes(data) }

func (osFileOps) Stat(path string) (os.FileInfo, error)     { return os.Stat(path) }
func (osFileOps) Chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
func (osFileOps) Rename(oldPath, newPath string) error      { return os.Rename(oldPath, newPath) }
func (osFileOps) Remove(path string) error                  { return os.Remove(path) }
func (osFileOps) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type LoadError struct {
	Database string
	Stage    string
	Err      error
}

func (e *LoadError) Error() string { return e.Database + ": " + e.Stage + ": " + e.Err.Error() }
func (e *LoadError) Unwrap() error { return e.Err }

type publisher struct {
	name string
	path func() string
	ops  fileOps
	mu   sync.Mutex
	published     bool
	diskAttempted bool
	holder        *readerHolder
}

func newPublisher(name string, path func() string) *publisher {
	return &publisher{name: name, path: path, ops: osFileOps{}, holder: &readerHolder{}}
}

func ResolveLink(path string) (string, error) { return resolveLink(path) }

func resolveLink(path string) (string, error) {
	const maxDepth = 8
	for i := 0; i < maxDepth; i++ {
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return path, nil
			}
			return "", fmt.Errorf("cannot inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", fmt.Errorf("cannot read the symlink at %s: %w", path, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return "", fmt.Errorf("more than %d symlinks deep, or a loop, at %s", maxDepth, path)
}

const defaultFileMode os.FileMode = 0o644

func (p *publisher) EnsureSeeded() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published || p.diskAttempted {
		return nil
	}
	p.diskAttempted = true
	reader, err := p.ops.Open(p.path())
	if err != nil {
		return &LoadError{Database: p.name, Stage: "open", Err: err}
	}
	p.holder.publish(reader)
	p.published = true
	return nil
}

func (p *publisher) Adopt(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.published {
		return nil
	}
	if err := checkDatabaseSize(p.name, int64(len(data))); err != nil {
		return &LoadError{Database: p.name, Stage: "size", Err: err}
	}
	reader, err := p.ops.FromBytes(data)
	if err != nil {
		return &LoadError{Database: p.name, Stage: "parse", Err: err}
	}
	p.holder.publish(reader)
	p.published = true
	return nil
}

func (p *publisher) Reopen() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	reader, err := p.ops.Open(p.path())
	if err != nil {
		return &LoadError{Database: p.name, Stage: "open", Err: err}
	}
	p.holder.publish(reader)
	p.published = true
	return nil
}

func (p *publisher) Publish(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(data) == 0 {
		return &LoadError{Database: p.name, Stage: "stage", Err: errors.New("no data")}
	}
	final, err := resolveLink(p.path())
	if err != nil {
		return &LoadError{Database: p.name, Stage: "resolve", Err: err}
	}
	dir := filepath.Dir(final)

	tmp, err := p.ops.CreateTemp(dir, filepath.Base(final)+".*.staging")
	if err != nil {
		return &LoadError{Database: p.name, Stage: "create temp file", Err: err}
	}
	tmpPath := tmp.Name()
	discard := func() { _ = tmp.Close(); _ = p.ops.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		discard()
		return &LoadError{Database: p.name, Stage: "write", Err: err}
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return &LoadError{Database: p.name, Stage: "fsync", Err: err}
	}
	if err := tmp.Close(); err != nil {
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "close", Err: err}
	}

	candidate, err := p.ops.Open(tmpPath)
	if err != nil {
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "verify", Err: err}
	}

	mode := defaultFileMode
	if info, err := p.ops.Stat(final); err == nil {
		mode = info.Mode().Perm()
	}
	if err := p.ops.Chmod(tmpPath, mode); err != nil {
		_ = candidate.Close()
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "chmod", Err: err}
	}

	if err := p.ops.Rename(tmpPath, final); err != nil {
		_ = candidate.Close()
		_ = p.ops.Remove(tmpPath)
		return &LoadError{Database: p.name, Stage: "rename", Err: err}
	}
	if err := p.ops.SyncDir(dir); err != nil {
		log.Warnln("[GEO] %s: directory fsync after rename failed: %v", p.name, err)
	}
	log.Infoln("[GEO] %s: published %s", p.name, candidate.Metadata.DatabaseType)
	p.holder.publish(candidate)
	p.published = true
	return nil
}

func databaseTypeOf(reader *maxminddb.Reader) databaseType {
	if reader == nil {
		return typeMaxmind
	}
	switch reader.Metadata.DatabaseType {
	case "sing-geoip":
		return typeSing
	case "Meta-geoip0":
		return typeMetaV0
	default:
		return typeMaxmind
	}
}
