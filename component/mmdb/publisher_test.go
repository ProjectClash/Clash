package mmdb

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestPublisher(t *testing.T) (*publisher, string) {
	t.Helper()
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	p := newPublisher("MMDB", func() string { return final })
	return p, final
}

func lookup(t *testing.T, h *readerHolder) []string {
	t.Helper()
	return IPReader{holder: h}.LookupCode(net.ParseIP("1.0.0.1"))
}

func TestPublishReplacesTheFileAndTheReaderTogether(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("after publishing A: %v", got)
	}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("after publishing B: %v", got)
	}
	onDisk, err := maxminddb.Open(final)
	if err != nil {
		t.Fatal(err)
	}
	defer onDisk.Close()
	var rec struct {
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	_ = onDisk.Lookup(net.ParseIP("1.0.0.1"), &rec)
	if rec.Country.ISO != "BB" {
		t.Fatalf("the file on disk answers %q, the reader answers bb", rec.Country.ISO)
	}
	entries, _ := os.ReadDir(filepath.Dir(final))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".staging") {
			t.Fatalf("a staging file survived: %s", e.Name())
		}
	}
}

func TestAnInFlightLookupKeepsTheOldReaderOpenUntilItLetsGo(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	closed := 0
	old := p.holder.acquire()
	old.close = func() { closed++ }
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if closed != 0 {
		t.Fatal("publish closed a reader that a lookup still holds")
	}
	if !old.retired {
		t.Fatal("the old snapshot was not retired by the publish")
	}
	if got := lookupCode(old.reader, old.databaseType, net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the in-flight lookup no longer reads its own reader: %v", got)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("new lookups do not see the new reader: %v", got)
	}
	p.holder.release(old)
	if closed != 1 {
		t.Fatalf("the last release must close the retired reader once, closed %d times", closed)
	}
	p.holder.release(p.holder.acquire())
	if closed != 1 {
		t.Fatal("a live reader was closed by a release")
	}
}

func TestAnUnheldOldReaderIsClosedByThePublish(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	closed := 0
	p.holder.current.close = func() { closed++ }
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("closed %d times, want 1", closed)
	}
}

type failingOps struct {
	osFileOps
	failAt string
	err    error
	order  []string
	mu     sync.Mutex
}

type failingTemp struct {
	tempFile
	ops *failingOps
}

func (f *failingOps) note(stage string) error {
	f.mu.Lock()
	f.order = append(f.order, stage)
	f.mu.Unlock()
	if stage == f.failAt {
		return f.err
	}
	return nil
}

func (f *failingOps) CreateTemp(dir, pattern string) (tempFile, error) {
	if err := f.note("create"); err != nil {
		return nil, err
	}
	tmp, err := f.osFileOps.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &failingTemp{tempFile: tmp, ops: f}, nil
}
func (t *failingTemp) Write(p []byte) (int, error) {
	if err := t.ops.note("write"); err != nil {
		return 0, err
	}
	return t.tempFile.Write(p)
}
func (t *failingTemp) Sync() error {
	if err := t.ops.note("fsync"); err != nil {
		return err
	}
	return t.tempFile.Sync()
}
func (t *failingTemp) Close() error {
	if err := t.ops.note("close"); err != nil {
		return err
	}
	return t.tempFile.Close()
}
func (f *failingOps) Open(path string) (*maxminddb.Reader, error) {
	if err := f.note("verify"); err != nil {
		return nil, err
	}
	return f.osFileOps.Open(path)
}
func (f *failingOps) Chmod(path string, mode os.FileMode) error {
	if err := f.note("chmod"); err != nil {
		return err
	}
	return f.osFileOps.Chmod(path, mode)
}
func (f *failingOps) Rename(oldPath, newPath string) error {
	if err := f.note("rename"); err != nil {
		return err
	}
	return f.osFileOps.Rename(oldPath, newPath)
}
func (f *failingOps) SyncDir(dir string) error {
	if err := f.note("syncdir"); err != nil {
		return err
	}
	return f.osFileOps.SyncDir(dir)
}

func stagingFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".staging") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestEveryStageBeforeTheRenameFailsClosed(t *testing.T) {
	for _, stage := range []string{"create", "write", "fsync", "close", "verify", "chmod", "rename"} {
		t.Run(stage, func(t *testing.T) {
			p, final := newTestPublisher(t)
			if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(final)
			injected := errors.New("injected " + stage + " failure")
			p.ops = &failingOps{failAt: stage, err: injected}

			err := p.Publish(fixture(t, "country-b.mmdb"))
			var loadErr *LoadError
			if !errors.As(err, &loadErr) || !errors.Is(err, injected) {
				t.Fatalf("want a LoadError wrapping the injected error, got %v", err)
			}
			if !strings.Contains(loadErr.Stage, stage) && !(stage == "create" && loadErr.Stage == "create temp file") {
				t.Fatalf("the error names stage %q, want %q", loadErr.Stage, stage)
			}
			if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
				t.Fatalf("the reader changed on a failed publish: %v", got)
			}
			after, _ := os.ReadFile(final)
			if string(after) != string(before) {
				t.Fatal("the last-known-good file changed on a failed publish")
			}
			if left := stagingFiles(t, filepath.Dir(final)); len(left) != 0 {
				t.Fatalf("staging files left behind: %v", left)
			}
		})
	}
}

func TestAFileThatDoesNotOpenNeverReachesTheFinalPath(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	ops := &failingOps{}
	p.ops = ops
	err := p.Publish([]byte("this is not a database"))
	var loadErr *LoadError
	if !errors.As(err, &loadErr) || loadErr.Stage != "verify" {
		t.Fatalf("want a verify LoadError, got %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the reader changed: %v", got)
	}
	if _, err := maxminddb.Open(final); err != nil {
		t.Fatalf("the last-known-good file on disk no longer opens: %v", err)
	}
	joined := strings.Join(ops.order, ",")
	if !strings.Contains(joined, "verify") || strings.Contains(joined, "rename") {
		t.Fatalf("verify must run and the rename must not: %s", joined)
	}
}

func TestADirectoryFsyncFailureIsAWarningNotARollback(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	p.ops = &failingOps{failAt: "syncdir", err: errors.New("injected syncdir failure")}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatalf("a directory fsync failure must not fail the publish: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the verified reader was not published: %v", got)
	}
}

func TestTheStagesRunInTheOrderThatCannotLoseTheLastKnownGood(t *testing.T) {
	p, _ := newTestPublisher(t)
	ops := &failingOps{}
	p.ops = ops
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	want := "create,write,fsync,close,verify,chmod,rename,syncdir"
	if got := strings.Join(ops.order, ","); got != want {
		t.Fatalf("stage order %s, want %s", got, want)
	}
}

func TestTheFileModeIsKeptAcrossAPublish(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(final, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want the previous file's 0600", info.Mode().Perm())
	}
}

type blockingOps struct {
	osFileOps
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingOps) CreateTemp(dir, pattern string) (tempFile, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.osFileOps.CreateTemp(dir, pattern)
}

func TestTheTransactionHoldsTheMutexEndToEnd(t *testing.T) {
	p, _ := newTestPublisher(t)
	ops := &blockingOps{entered: make(chan struct{}), release: make(chan struct{})}
	p.ops = ops
	done := make(chan error, 1)
	go func() { done <- p.Publish(fixture(t, "country-a.mmdb")) }()
	<-ops.entered
	if p.mu.TryLock() {
		p.mu.Unlock()
		t.Fatal("the publisher's mutex is free while a publish is inside the transaction")
	}
	close(ops.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !p.mu.TryLock() {
		t.Fatal("the mutex was not released after the publish returned")
	}
	p.mu.Unlock()
	p.ops = osFileOps{}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the later publish must win: %v", got)
	}
}

func TestEmptyDataIsRefused(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(nil); err == nil {
		t.Fatal("empty data must be refused")
	}
}

func TestASNPublishAnswersFromTheNewFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "ASN.mmdb")
	p := newPublisher("ASN", func() string { return final })
	if err := p.Publish(fixture(t, "asn-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if number, org := (ASNReader{holder: p.holder}).LookupASN(net.ParseIP("1.0.0.1")); number != "64500" || org != "Fixture A" {
		t.Fatalf("A: %q %q", number, org)
	}
	if err := p.Publish(fixture(t, "asn-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if number, org := (ASNReader{holder: p.holder}).LookupASN(net.ParseIP("1.0.0.1")); number != "64501" || org != "Fixture B" {
		t.Fatalf("B: %q %q", number, org)
	}
}

type blockingOpenOps struct {
	osFileOps
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingOpenOps) Open(path string) (*maxminddb.Reader, error) {
	first := false
	b.once.Do(func() { first = true; close(b.entered) })
	if first {
		<-b.release
	}
	return b.osFileOps.Open(path)
}

type failingOpenOps struct{ osFileOps }

func (failingOpenOps) Open(string) (*maxminddb.Reader, error) {
	return nil, errors.New("not a database")
}

func TestReopenHoldsTheMutex(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops := &blockingOpenOps{entered: make(chan struct{}), release: make(chan struct{})}
	p.ops = ops
	done := make(chan error, 1)
	go func() { done <- p.Reopen() }()
	<-ops.entered
	if p.mu.TryLock() {
		p.mu.Unlock()
		t.Fatal("the publisher's mutex is free while a reopen is inside Open")
	}
	close(ops.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !p.mu.TryLock() {
		t.Fatal("the publisher's mutex is still held after Reopen returned")
	}
	p.mu.Unlock()
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("reopen did not publish the file on disk: %v", got)
	}
}

func TestAReopenParkedBeforePublishCannotShadowAnUpdate(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops := &blockingOpenOps{entered: make(chan struct{}), release: make(chan struct{})}
	p.ops = ops
	reopened := make(chan error, 1)
	go func() { reopened <- p.Reopen() }()
	<-ops.entered

	published := make(chan error, 1)
	go func() { published <- p.Publish(fixture(t, "country-b.mmdb")) }()
	select {
	case err := <-published:
		t.Fatalf("the update completed while a reopen was inside the transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(ops.release)
	if err := <-reopened; err != nil {
		t.Fatal(err)
	}
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the reader in memory is not the update that ran last: %v", got)
	}
}

func TestReopenKeepsTheCurrentReaderWhenTheFileDoesNotOpen(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	p.ops = failingOpenOps{}
	err := p.Reopen()
	var le *LoadError
	if !errors.As(err, &le) || le.Stage != "open" {
		t.Fatalf("want a LoadError at the open stage, got %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("a reopen that failed to open replaced the reader: %v", got)
	}
}

func TestFixturesCarryThePinnedBuildEpoch(t *testing.T) {
	const pinnedBuildEpoch = 1_700_000_000
	for _, name := range []string{"country-a.mmdb", "country-b.mmdb", "asn-a.mmdb", "asn-b.mmdb", "metav0-no-description.mmdb", "metav0-mixed-record.mmdb", "ipinfo-short-asn.mmdb"} {
		reader, err := maxminddb.FromBytes(fixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if reader.Metadata.BuildEpoch != pinnedBuildEpoch {
			t.Fatalf("%s: build epoch %d, want the pinned %d -- regenerate with testdata/gen", name, reader.Metadata.BuildEpoch, pinnedBuildEpoch)
		}
		_ = reader.Close()
	}
}

func TestTheTransactionAcceptsADatabaseWithNoDescription(t *testing.T) {
	data := fixture(t, "metav0-no-description.mmdb")

	probe, err := maxminddb.FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(probe.Metadata.Description) != 0 {
		t.Fatalf("the fixture no longer has the shape it is here for: description=%v", probe.Metadata.Description)
	}
	if probe.Verify() == nil {
		t.Fatal("the fixture passes Reader.Verify(), so it cannot pin the case that Verify rejects")
	}
	_ = probe.Close()

	p, final := newTestPublisher(t)
	if err := p.Publish(data); err != nil {
		t.Fatalf("the transaction refused a database with no description -- this is the real geoip.metadb: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 2 || got[0] != "cc" || got[1] != "dd" {
		t.Fatalf("the published reader does not answer from the new database: %v", got)
	}
	if _, err := os.Stat(final); err != nil {
		t.Fatalf("the database was not committed to the final path: %v", err)
	}

	q := newPublisher("MMDB", func() string { return final })
	if err := q.Reopen(); err != nil {
		t.Fatalf("reopening a committed database with no description failed: %v", err)
	}
	if got := lookup(t, q.holder); len(got) != 2 || got[0] != "cc" {
		t.Fatalf("the reopened reader does not answer: %v", got)
	}
}

func TestAFailedFirstUpdateLeavesTheDatabaseOnDiskReachable(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedPublisher := ipPublisher
	defer func() { ipPublisher = savedPublisher }()
	ipPublisher = newPublisher("MMDB", func() string { return final })

	if err := PublishIP([]byte("not a database, but not empty either")); err == nil {
		t.Fatal("the transaction accepted bytes that are not a database")
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("a failed update stranded the valid database on disk: lookup answered %v, want [aa]", got)
	}
	if err := PublishIP(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the good update did not take: %v", got)
	}
}

func TestLoadFromBytesThatDoesNotParseSeedsNothing(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := ipPublisher
	defer func() { ipPublisher = saved }()
	ipPublisher = newPublisher("MMDB", func() string { return final })

	LoadFromBytes([]byte("not a database"))
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("bytes that do not parse stranded the database on disk: %v, want [aa]", got)
	}
}

func TestLoadFromBytesWinsAndTheFirstOneWins(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(final, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := ipPublisher
	defer func() { ipPublisher = saved }()
	ipPublisher = newPublisher("MMDB", func() string { return final })

	LoadFromBytes(fixture(t, "country-b.mmdb"))
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the in-memory load did not win: %v", got)
	}
	LoadFromBytes(fixture(t, "country-a.mmdb"))
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("a second load overwrote the first: %v", got)
	}
	if err := PublishIP(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := IPInstance().LookupCode(net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("an update after an in-memory load did not take: %v", got)
	}
}

func TestAMissingDatabaseIsOpenedOnceNotPerLookup(t *testing.T) {
	p, _ := newTestPublisher(t)
	counter := &countingOps{}
	p.ops = counter
	for i := 0; i < 5; i++ {
		_ = p.EnsureSeeded()
	}
	if counter.opens != 1 {
		t.Fatalf("the disk was opened %d times, want 1", counter.opens)
	}
}

type countingOps struct {
	osFileOps
	opens int
}

func (c *countingOps) Open(path string) (*maxminddb.Reader, error) {
	c.opens++
	return c.osFileOps.Open(path)
}

func TestPublishingThroughASymlinkKeepsTheLink(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(shared, "Country.mmdb")
	if err := os.WriteFile(real, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "Country.mmdb")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	p := newPublisher("MMDB", func() string { return link })
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the transaction replaced the symlink with a regular file")
	}
	got, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(fixture(t, "country-b.mmdb")) {
		t.Fatal("the update did not land on the file the link points at")
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the published reader is not the new database: %v", got)
	}
	for _, dir := range []string{root, shared} {
		names, _ := os.ReadDir(dir)
		for _, n := range names {
			if strings.Contains(n.Name(), ".staging") {
				t.Fatalf("a staging file was left in %s: %s", dir, n.Name())
			}
		}
	}
}

func TestPublishingThroughADanglingSymlinkKeepsTheLink(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(shared, "Country.mmdb")
	link := filepath.Join(root, "Country.mmdb")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	p := newPublisher("MMDB", func() string { return link })
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the transaction replaced a dangling symlink with a regular file")
	}
	if _, err := os.Stat(real); err != nil {
		t.Fatalf("the database did not land on the link's target: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the published reader is not the new database: %v", got)
	}
}

func TestResolveLinkFollowsRelativeAndChainedLinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real.mmdb")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first.mmdb")
	if err := os.Symlink("real.mmdb", first); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(root, "second.mmdb")
	if err := os.Symlink(first, second); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{first, second} {
		got, err := resolveLink(path)
		if err != nil || got != real {
			t.Fatalf("resolveLink(%q) = %q, %v; want %q", path, got, err, real)
		}
	}
	plain := filepath.Join(root, "plain.mmdb")
	if got, err := resolveLink(plain); err != nil || got != plain {
		t.Fatalf("a path that is not a link must come back unchanged: %q, %v", got, err)
	}
}

func TestResolveLinkFailsClosedOnADeepChainAndALoop(t *testing.T) {
	root := t.TempDir()
	deepest := filepath.Join(root, "real.mmdb")
	if err := os.WriteFile(deepest, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := deepest
	for i := 0; i < 9; i++ {
		link := filepath.Join(root, "link"+strconv.Itoa(i)+".mmdb")
		if err := os.Symlink(previous, link); err != nil {
			t.Fatal(err)
		}
		previous = link
	}
	if got, err := resolveLink(previous); err == nil {
		t.Fatalf("a chain past the bound resolved to %q instead of failing", got)
	}
	a, b := filepath.Join(root, "a.mmdb"), filepath.Join(root, "b.mmdb")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveLink(a); err == nil {
		t.Fatalf("a loop resolved to %q instead of failing", got)
	}
	p := newPublisher("MMDB", func() string { return a })
	if err := p.Publish(fixture(t, "country-a.mmdb")); err == nil {
		t.Fatal("a publish through a symlink loop was accepted")
	}
}

func TestARecordTheLookupDidNotExpectIsNoMatchNotAPanic(t *testing.T) {
	t.Run("a Meta-geoip0 list with a non-string element", func(t *testing.T) {
		p, _ := newTestPublisher(t)
		if err := p.Publish(fixture(t, "metav0-mixed-record.mmdb")); err != nil {
			t.Fatal(err)
		}
		got := IPReader{holder: p.holder}.LookupCode(net.ParseIP("1.0.0.1"))
		if len(got) != 1 || got[0] != "us" {
			t.Fatalf("the strings in a mixed record should still answer: %v", got)
		}
	})
	t.Run("an ipinfo record whose asn is too short for its prefix", func(t *testing.T) {
		p, _ := newTestPublisher(t)
		if err := p.Publish(fixture(t, "ipinfo-short-asn.mmdb")); err != nil {
			t.Fatal(err)
		}
		asn, name := ASNReader{holder: p.holder}.LookupASN(net.ParseIP("1.0.0.1"))
		if asn != "" || name != "Fixture" {
			t.Fatalf("a short asn should answer empty, not panic: %q, %q", asn, name)
		}
	})
}

func TestNothingAfterTheCommitCanStrandMemoryBehindDisk(t *testing.T) {
	p, final := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("setup: %v", got)
	}

	ops := &failingAfterFirstOpenOps{}
	p.ops = ops
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatalf("a publish must not depend on an open after the rename: %v", err)
	}
	if data, err := os.ReadFile(final); err != nil || string(data) != string(fixture(t, "country-b.mmdb")) {
		t.Fatalf("the commit did not happen: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("memory did not follow disk: %v", got)
	}
	if ops.opens != 1 {
		t.Fatalf("the transaction opened the database %d times; the candidate is the published reader, so it opens once", ops.opens)
	}
}

type failingAfterFirstOpenOps struct {
	osFileOps
	opens int
}

func (f *failingAfterFirstOpenOps) Open(path string) (*maxminddb.Reader, error) {
	f.opens++
	if f.opens >= 2 {
		return nil, errors.New("injected open failure after the candidate")
	}
	return f.osFileOps.Open(path)
}

func TestAReplacementLandsWhileTheCurrentReaderIsStillLive(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	live := p.holder.acquire()
	if live == nil {
		t.Fatal("no snapshot after the first publish")
	}
	defer p.holder.release(live)

	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatalf("a replacement failed while a reader was live: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "bb" {
		t.Fatalf("the new database is not what answers now: %v", got)
	}
	if got := lookupCode(live.reader, live.databaseType, net.ParseIP("1.0.0.1")); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the reader held across the replacement stopped answering: %v", got)
	}
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatalf("a later replacement failed: %v", err)
	}
	if got := lookup(t, p.holder); len(got) != 1 || got[0] != "aa" {
		t.Fatalf("the third database is not what answers: %v", got)
	}
}

func TestADatabaseLargerThanTheCeilingIsNotOpened(t *testing.T) {
	dir := t.TempDir()

	over := filepath.Join(dir, "over.mmdb")
	f, err := os.Create(over)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxDatabaseBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	reader, err := openDatabaseFile(over)
	if err == nil {
		reader.Close()
		t.Fatal("a file past the ceiling must not open")
	}
	if !strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("the refusal must name the ceiling, got %v", err)
	}

	at := filepath.Join(dir, "at.mmdb")
	g, err := os.Create(at)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Truncate(MaxDatabaseBytes); err != nil {
		t.Fatal(err)
	}
	g.Close()

	reader, err = openDatabaseFile(at)
	if err == nil {
		reader.Close()
		t.Fatal("a file of zeros is not a database")
	}
	if strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("a file at the ceiling must not be refused for its size, got %v", err)
	}
}

func writeOversizedButValidDatabase(t *testing.T, path string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("testdata", "country-a.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(source); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(MaxDatabaseBytes+1-int64(len(source)), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(source); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAnswersWhatTheRuntimeOpenAnswers(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.mmdb")
	source, err := os.ReadFile(filepath.Join("testdata", "country-a.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, source, 0o644); err != nil {
		t.Fatal(err)
	}

	garbage := filepath.Join(dir, "garbage.mmdb")
	if err := os.WriteFile(garbage, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(dir, "empty.mmdb")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	oversized := filepath.Join(dir, "oversized.mmdb")
	writeOversizedButValidDatabase(t, oversized)

	for _, c := range []struct {
		path string
		want bool
	}{
		{valid, true},
		{garbage, false},
		{empty, false},
		{oversized, false},
		{filepath.Join(dir, "absent.mmdb"), false},
	} {
		reader, err := openDatabaseFile(c.path)
		if err == nil {
			reader.Close()
		}
		runtimeOpens := err == nil
		verified := Verify(c.path)
		if verified != runtimeOpens {
			t.Fatalf("%s: Verify says %v, the runtime open says %v -- initialisation and the first lookup must agree",
				filepath.Base(c.path), verified, runtimeOpens)
		}
		if verified != c.want {
			t.Fatalf("%s: both doors say %v, want %v", filepath.Base(c.path), verified, c.want)
		}
	}
}

func TestAdoptRefusesABufferPastTheCeiling(t *testing.T) {
	p := newPublisher("MMDB", func() string { return filepath.Join(t.TempDir(), "Country.mmdb") })
	if err := p.Adopt(make([]byte, MaxDatabaseBytes+1)); err == nil {
		t.Fatal("a buffer past the ceiling must not be adopted")
	} else if !strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("the refusal must name the ceiling, got %v", err)
	}
	if p.published {
		t.Fatal("a refused buffer must not count as published")
	}
}

func TestAnUnreadableSymlinkFailsTheResolveRatherThanPassingItThrough(t *testing.T) {
	dir := t.TempDir()

	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(locked, "Country.mmdb")
	if err := os.WriteFile(target, fixture(t, "country-a.mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	if _, err := resolveLink(target); err == nil {
		t.Fatal("an unreadable path must fail the resolve, not pass through")
	} else if !strings.Contains(err.Error(), "cannot inspect") {
		t.Fatalf("the failure must say the inspection did not happen, got %v", err)
	}

	absent := filepath.Join(dir, "absent.mmdb")
	if got, err := resolveLink(absent); err != nil || got != absent {
		t.Fatalf("a missing file is a first download, got %q %v", got, err)
	}
}
