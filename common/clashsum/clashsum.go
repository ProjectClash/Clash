package clashsum

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Stamp struct {
	dev, ino          uint64
	size              int64
	modified, changed int64
}

func StampOf(info os.FileInfo) (Stamp, bool) {
	if info == nil || !info.Mode().IsRegular() {
		return Stamp{}, false
	}
	return stampOf(info)
}

var racyMargin = platformRacyMargin

const racyMarginWholeSeconds = 2 * time.Second

func settled(s Stamp, at time.Time) bool {
	margin := racyMargin
	if s.changed%int64(time.Second) == 0 && s.modified%int64(time.Second) == 0 && margin < racyMarginWholeSeconds {
		margin = racyMarginWholeSeconds
	}
	return s.changed <= at.Add(-margin).UnixNano()
}

type identity struct{ dev, ino uint64 }

type proof struct {
	stamp Stamp
	sum   [sha256.Size]byte
}

const maxProofs = 64

var proofs struct {
	sync.Mutex
	files map[identity]proof
}

func Proven(s Stamp, sum [sha256.Size]byte) bool {
	proofs.Lock()
	defer proofs.Unlock()
	p, ok := proofs.files[identity{s.dev, s.ino}]
	return ok && p.stamp == s && p.sum == sum
}

func Prove(s Stamp, at time.Time, sum [sha256.Size]byte) {
	if s.ino == 0 && s.dev == 0 || !settled(s, at) {
		return
	}
	proofs.Lock()
	defer proofs.Unlock()
	if proofs.files == nil || len(proofs.files) >= maxProofs {
		proofs.files = make(map[identity]proof)
	}
	proofs.files[identity{s.dev, s.ino}] = proof{stamp: s, sum: sum}
}

var hashed atomic.Int64

func Hashed() int64 { return hashed.Load() }

func Sum(data []byte) [sha256.Size]byte {
	hashed.Add(1)
	return sha256.Sum256(data)
}

var ErrNotWhole = errors.New("its last bytes are not the SHA-256 of the rest")

func Check(path string) ([sha256.Size]byte, error) {
	var trailer [sha256.Size]byte
	at := time.Now()
	file, err := openFile(path)
	if err != nil {
		return trailer, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return trailer, err
	}
	if !info.Mode().IsRegular() || info.Size() < sha256.Size {
		return trailer, fmt.Errorf("%s is not a regular file of %d bytes or more", path, sha256.Size)
	}
	if _, err := file.ReadAt(trailer[:], info.Size()-sha256.Size); err != nil {
		return trailer, err
	}
	stamp, stamped := StampOf(info)
	if stamped && ProvenAt(path, stamp, trailer) {
		return trailer, nil
	}
	hashed.Add(1)
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, info.Size()-sha256.Size); err != nil {
		return trailer, err
	}
	if [sha256.Size]byte(hash.Sum(nil)) != trailer {
		return trailer, ErrNotWhole
	}
	if stamped {
		Prove(stamp, at, trailer)
	}
	return trailer, nil
}

func Hashes(path string, want [sha256.Size]byte) bool {
	sum, err := Check(path)
	return err == nil && sum == want
}

const ProofSuffix = ".proof"

const maxPersistWait = 10 * time.Millisecond

const ProofTemporaryPrefix = ".clashsum-"

const proofVersion = "clashsum 1"

const maxProofBytes = 256

func (s Stamp) text(sum [sha256.Size]byte) string {
	return fmt.Sprintf("%s\n%d %d %d %d %d\n%x\n", proofVersion, s.dev, s.ino, s.size, s.modified, s.changed, sum)
}

func ProvenAt(path string, s Stamp, sum [sha256.Size]byte) bool {
	if Proven(s, sum) {
		return true
	}
	if s.ino == 0 && s.dev == 0 {
		return false
	}
	file, err := openFile(path + ProofSuffix)
	if err != nil {
		return false
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() > maxProofBytes {
		return false
	}
	text, err := io.ReadAll(io.LimitReader(file, maxProofBytes))
	if err != nil || string(text) != s.text(sum) {
		return false
	}
	proofs.Lock()
	defer proofs.Unlock()
	if proofs.files == nil || len(proofs.files) >= maxProofs {
		proofs.files = make(map[identity]proof)
	}
	proofs.files[identity{s.dev, s.ino}] = proof{stamp: s, sum: sum}
	return true
}

func Persist(path string, touch bool) ([sha256.Size]byte, bool, error) {
	settle(path)
	sum, err := Check(path)
	if err != nil {
		return sum, false, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return sum, false, nil
	}
	stamp, ok := StampOf(info)
	if !ok || !Proven(stamp, sum) {
		return sum, false, nil
	}
	return sum, leaveProof(path, stamp, sum, touch), nil
}

func ProveWritten(path string, sum [sha256.Size]byte) bool {
	settle(path)
	at := time.Now()
	file, err := openFile(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < sha256.Size {
		return false
	}
	var trailer [sha256.Size]byte
	if _, err := file.ReadAt(trailer[:], info.Size()-sha256.Size); err != nil || trailer != sum {
		return false
	}
	stamp, ok := StampOf(info)
	if !ok {
		return false
	}
	Prove(stamp, at, sum)
	if !Proven(stamp, sum) {
		return false
	}
	return leaveProof(path, stamp, sum, true)
}

func settle(path string) {
	if info, err := os.Stat(path); err == nil {
		if stamp, ok := StampOf(info); ok {
			if wait := time.Until(time.Unix(0, stamp.changed).Add(racyMargin)); wait > 0 && wait <= maxPersistWait {
				time.Sleep(wait)
			}
		}
	}
}

func leaveProof(path string, stamp Stamp, sum [sha256.Size]byte, touch bool) bool {
	want := stamp.text(sum)
	proofPath := path + ProofSuffix
	if !touch {
		if file, err := openFile(proofPath); err == nil {
			text, _ := io.ReadAll(io.LimitReader(file, maxProofBytes))
			file.Close()
			if string(text) == want {
				return true
			}
		}
	}
	return writeProof(proofPath, want) == nil
}

func writeProof(path, text string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ProofTemporaryPrefix+"*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(text)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
