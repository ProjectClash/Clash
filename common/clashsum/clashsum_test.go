package clashsum

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func summed(body string) ([]byte, [sha256.Size]byte) {
	sum := sha256.Sum256([]byte(body))
	return append([]byte(body), sum[:]...), sum
}

func withMargin(t *testing.T, margin time.Duration) {
	t.Helper()
	saved := racyMargin
	racyMargin = margin
	t.Cleanup(func() { racyMargin = saved })
}

func writeSummed(t *testing.T, path, body string) [sha256.Size]byte {
	t.Helper()
	data, sum := summed(body)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return sum
}

func checkCounting(t *testing.T, path string) ([sha256.Size]byte, error, int64) {
	t.Helper()
	before := Hashed()
	sum, err := Check(path)
	return sum, err, Hashed() - before
}

func TestAFileProvedIsNotHashedAgainUntilItChanges(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	withMargin(t, 0)
	path := filepath.Join(t.TempDir(), "x.index")
	want := writeSummed(t, path, "the rules, compiled")
	for i, wantHashes := range []int64{1, 0, 0} {
		sum, err, hashes := checkCounting(t, path)
		if err != nil || sum != want {
			t.Fatalf("check %d: %x, %v", i, sum, err)
		}
		if hashes != wantHashes {
			t.Fatalf("check %d hashed the file %d times, want %d", i, hashes, wantHashes)
		}
	}
	if !Hashes(path, want) || Hashes(path, [sha256.Size]byte{1}) {
		t.Fatal("Hashes does not answer the trailer Check proved")
	}
}

func TestAFileChangedInPlaceIsHashedAgain(t *testing.T) {
	withMargin(t, 0)
	path := filepath.Join(t.TempDir(), "x.index")
	writeSummed(t, path, "the rules, compiled")
	if _, err := Check(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("T"), 0); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	_, err, hashes := checkCounting(t, path)
	if !errors.Is(err, ErrNotWhole) || hashes != 1 {
		t.Fatalf("a file changed in place: %v after %d hashes", err, hashes)
	}
}

func TestAFileReplacedIsHashedItself(t *testing.T) {
	withMargin(t, 0)
	directory := t.TempDir()
	path := filepath.Join(directory, "x.index")
	writeSummed(t, path, "the rules, compiled")
	if _, err := Check(path); err != nil {
		t.Fatal(err)
	}
	other := writeSummed(t, filepath.Join(directory, "next"), "other rules, compiled")
	if err := os.Rename(filepath.Join(directory, "next"), path); err != nil {
		t.Fatal(err)
	}
	sum, err, hashes := checkCounting(t, path)
	if err != nil || sum != other || hashes != 1 {
		t.Fatalf("a replaced file: %x, %v after %d hashes", sum, err, hashes)
	}
}

func TestAFileJustChangedIsHashedAtEachOpen(t *testing.T) {
	withMargin(t, time.Hour)
	path := filepath.Join(t.TempDir(), "x.index")
	writeSummed(t, path, "the rules, compiled")
	for i := 0; i < 2; i++ {
		if _, err, hashes := checkCounting(t, path); err != nil || hashes != 1 {
			t.Fatalf("check %d: %v after %d hashes", i, err, hashes)
		}
	}
}

func TestAWholeSecondChangeSettlesAfterTwoSeconds(t *testing.T) {
	withMargin(t, 0)
	changed := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	s := Stamp{dev: 1, ino: 2, size: 3, modified: changed.UnixNano(), changed: changed.UnixNano()}
	if settled(s, changed.Add(time.Second)) || !settled(s, changed.Add(2*time.Second)) {
		t.Fatal("a whole-second change settled at the wrong time")
	}
	s.changed++
	if !settled(s, changed.Add(time.Nanosecond)) {
		t.Fatal("a nanosecond change did not settle at the margin")
	}
}

func TestAFileThatIsNotWholeIsRefused(t *testing.T) {
	withMargin(t, 0)
	directory := t.TempDir()
	short := filepath.Join(directory, "short")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(short); err == nil {
		t.Fatal("a file shorter than a SHA-256 was answered")
	}
	damaged := filepath.Join(directory, "damaged")
	data, _ := summed("the rules, compiled")
	data[0] ^= 1
	if err := os.WriteFile(damaged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(damaged); !errors.Is(err, ErrNotWhole) {
		t.Fatalf("a damaged file: %v", err)
	}
	if _, err := Check(damaged); !errors.Is(err, ErrNotWhole) {
		t.Fatalf("a damaged file checked again: %v", err)
	}
}

func TestProofsAreBounded(t *testing.T) {
	withMargin(t, 0)
	directory := t.TempDir()
	first := filepath.Join(directory, "0")
	writeSummed(t, first, "0")
	if _, err := Check(first); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxProofs; i++ {
		path := filepath.Join(directory, string(rune('a'+i%26))+time.Now().Format("150405.000000000"))
		writeSummed(t, path, path)
		if _, err := Check(path); err != nil {
			t.Fatal(err)
		}
	}
	proofs.Lock()
	n := len(proofs.files)
	proofs.Unlock()
	if n > maxProofs {
		t.Fatalf("%d proofs kept", n)
	}
}

func forget() {
	proofs.Lock()
	proofs.files = nil
	proofs.Unlock()
}

func TestAProofBesideAFileIsTakenByTheNextProcess(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	withMargin(t, 0)
	path := filepath.Join(t.TempDir(), "x.index")
	want := writeSummed(t, path, "the rules, compiled")
	if sum, left, err := Persist(path, false); err != nil || !left || sum != want {
		t.Fatalf("Persist: %x %v %v", sum, left, err)
	}
	forget()
	if sum, err, hashes := checkCounting(t, path); err != nil || sum != want || hashes != 0 {
		t.Fatalf("the next process: %x, %v after %d hashes", sum, err, hashes)
	}
	info, _ := os.Stat(path)
	file, _ := os.OpenFile(path, os.O_WRONLY, 0)
	_, _ = file.WriteAt([]byte("T"), 0)
	file.Close()
	_ = os.Chtimes(path, info.ModTime(), info.ModTime())
	forget()
	if _, err, hashes := checkCounting(t, path); !errors.Is(err, ErrNotWhole) || hashes != 1 {
		t.Fatalf("a file changed under its proof: %v after %d hashes", err, hashes)
	}
}

func TestAProofThatIsNotTheFilesIsNotTaken(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	withMargin(t, 0)
	directory := t.TempDir()
	path := filepath.Join(directory, "x.index")
	writeSummed(t, path, "the rules, compiled")
	other := filepath.Join(directory, "y.index")
	writeSummed(t, other, "other rules, compiled")
	if _, left, err := Persist(other, false); err != nil || !left {
		t.Fatal(err)
	}
	proof, _ := os.ReadFile(other + ProofSuffix)
	for name, text := range map[string]string{
		"another file's": string(proof),
		"cut short":      string(proof[:len(proof)/2]),
		"another form":   "clashsum 2\n" + string(proof[len("clashsum 1\n"):]),
		"empty":          "",
	} {
		if err := os.WriteFile(path+ProofSuffix, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		forget()
		if _, err, hashes := checkCounting(t, path); err != nil || hashes != 1 {
			t.Errorf("%s proof: %v after %d hashes", name, err, hashes)
		}
	}
}

func TestAProofIsWrittenAgainOnlyWhenTouchedOrStale(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	withMargin(t, 0)
	path := filepath.Join(t.TempDir(), "x.index")
	writeSummed(t, path, "the rules, compiled")
	if _, _, err := Persist(path, false); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path+ProofSuffix, old, old); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Persist(path, false); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path + ProofSuffix); !info.ModTime().Equal(old.Truncate(time.Microsecond)) && !info.ModTime().Equal(old) {
		t.Fatalf("a proof that was the file's was written again: %v", info.ModTime())
	}
	if _, _, err := Persist(path, true); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path + ProofSuffix); !info.ModTime().After(old.Add(time.Minute)) {
		t.Fatal("a touched proof kept its time")
	}
}

func TestAFileJustWrittenIsPersistedOnApplePlatforms(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the Apple platforms' margin")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "x.index")
	writeSummed(t, filepath.Join(directory, "tmp"), "the rules, compiled")
	if err := os.Rename(filepath.Join(directory, "tmp"), path); err != nil {
		t.Fatal(err)
	}
	if _, left, err := Persist(path, false); err != nil || !left {
		t.Fatalf("a file just renamed: left %v, %v", left, err)
	}
}

func TestAWrittenFileIsProvedByItsSum(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	withMargin(t, 0)
	path := filepath.Join(t.TempDir(), "x.index")
	want := writeSummed(t, path, "the rules, compiled")
	before := Hashed()
	if ProveWritten(path, [sha256.Size]byte{1}) {
		t.Fatal("another sum proved the file")
	}
	if !ProveWritten(path, want) {
		t.Fatal("its sum did not prove the file")
	}
	if hashes := Hashed() - before; hashes != 0 {
		t.Fatalf("proving a written file hashed it %d times", hashes)
	}
	forget()
	if _, err, hashes := checkCounting(t, path); err != nil || hashes != 0 {
		t.Fatalf("the next process: %v after %d hashes", err, hashes)
	}
}

func TestAProofThatCannotBeWrittenLeavesTheFileWhole(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no change time on this platform")
	}
	withMargin(t, 0)
	path := filepath.Join(t.TempDir(), "x.index")
	want := writeSummed(t, path, "the rules, compiled")
	if err := os.Mkdir(path+ProofSuffix, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+ProofSuffix, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sum, left, err := Persist(path, true)
	if err != nil || left || sum != want {
		t.Fatalf("Persist: %x left %v, %v", sum, left, err)
	}
}
