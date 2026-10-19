package mtproto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)


var (
	tagAbridgedBytes     = [4]byte{0xef, 0xef, 0xef, 0xef}
	tagIntermediateBytes = [4]byte{0xee, 0xee, 0xee, 0xee}
	tagPaddedBytes       = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}
)

func testCTR(t *testing.T, key, iv []byte) cipher.Stream {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher.NewCTR(block, iv)
}

func testKey(raw, secret []byte) []byte {
	if secret == nil {
		return raw
	}
	sum := sha256.Sum256(append(append([]byte(nil), raw...), secret...))
	return sum[:]
}

func reverse64(frame [64]byte) (out [64]byte) {
	for i := range frame {
		out[63-i] = frame[i]
	}
	return
}

func testClientInit(t *testing.T, secret []byte, tag [4]byte, dc int16) (wire [64]byte, encrypt, decrypt cipher.Stream) {
	t.Helper()
	var frame [64]byte
	for {
		if _, err := rand.Read(frame[:]); err != nil {
			t.Fatal(err)
		}
		if frame[0] != 0xef && binary.LittleEndian.Uint32(frame[4:8]) != 0 {
			break
		}
	}
	copy(frame[56:60], tag[:])
	binary.LittleEndian.PutUint16(frame[60:62], uint16(dc))
	rev := reverse64(frame)
	encrypt = testCTR(t, testKey(frame[8:40], secret), frame[40:56])
	decrypt = testCTR(t, testKey(rev[8:40], secret), rev[40:56])
	var encrypted [64]byte
	encrypt.XORKeyStream(encrypted[:], frame[:])
	wire = frame
	copy(wire[56:], encrypted[56:])
	return
}

func testServerInit(t *testing.T, wire [64]byte) (tag [4]byte, dc int16, decrypt, encrypt cipher.Stream) {
	t.Helper()
	rev := reverse64(wire)
	decrypt = testCTR(t, wire[8:40], wire[40:56])
	encrypt = testCTR(t, rev[8:40], rev[40:56])
	var plain [64]byte
	decrypt.XORKeyStream(plain[:], wire[:])
	copy(tag[:], plain[56:60])
	dc = int16(binary.LittleEndian.Uint16(plain[60:62]))
	return
}

func mustSecret(t *testing.T, s string) Secret {
	t.Helper()
	secret, err := ParseSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

const testSecretHex = "00112233445566778899aabbccddeeff"

func TestObfuscated2RoundTrip(t *testing.T) {
	secret := mustSecret(t, testSecretHex)
	for _, dc := range []int16{1, 2, -2, 5, -4} {
		wire, clientEncrypt, clientDecrypt := testClientInit(t, secret.key[:], tagIntermediateBytes, dc)
		got, err := acceptInit(&wire, secret)
		if err != nil {
			t.Fatalf("dc %d: %v", dc, err)
		}
		if got.tag != tagIntermediateBytes || got.dc != dc {
			t.Fatalf("dc %d: read tag %x dc %d", dc, got.tag, got.dc)
		}

		upload := []byte("an MTProto transport packet from the client")
		sealed := make([]byte, len(upload))
		clientEncrypt.XORKeyStream(sealed, upload)
		got.decrypt.XORKeyStream(sealed, sealed)
		if !bytes.Equal(sealed, upload) {
			t.Fatalf("dc %d: server read %q", dc, sealed)
		}

		download := []byte("the DC's answer, back to the client")
		sealed = make([]byte, len(download))
		got.encrypt.XORKeyStream(sealed, download)
		clientDecrypt.XORKeyStream(sealed, sealed)
		if !bytes.Equal(sealed, download) {
			t.Fatalf("dc %d: client read %q", dc, sealed)
		}
	}
}

func TestObfuscated2WrongSecretIsRefused(t *testing.T) {
	server := mustSecret(t, testSecretHex)
	other := mustSecret(t, "ffeeddccbbaa99887766554433221100")
	for i := 0; i < 64; i++ {
		wire, _, _ := testClientInit(t, other.key[:], tagIntermediateBytes, 2)
		if _, err := acceptInit(&wire, server); err == nil {
			t.Fatal("an init made with another secret was accepted")
		}
	}
	wire, _, _ := testClientInit(t, nil, tagIntermediateBytes, 2)
	if _, err := acceptInit(&wire, server); err == nil {
		t.Fatal("an init made without the secret was accepted")
	}
}

func TestObfuscated2ProtocolTags(t *testing.T) {
	bare := mustSecret(t, testSecretHex)
	padded := mustSecret(t, "dd"+testSecretHex)
	unknown := [4]byte{0x01, 0x02, 0x03, 0x04}
	for _, c := range []struct {
		name   string
		secret Secret
		tag    [4]byte
		ok     bool
	}{
		{"bare abridged", bare, tagAbridgedBytes, true},
		{"bare intermediate", bare, tagIntermediateBytes, true},
		{"bare padded", bare, tagPaddedBytes, true},
		{"bare unknown", bare, unknown, false},
		{"dd abridged", padded, tagAbridgedBytes, false},
		{"dd intermediate", padded, tagIntermediateBytes, false},
		{"dd padded", padded, tagPaddedBytes, true},
		{"dd unknown", padded, unknown, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire, _, _ := testClientInit(t, c.secret.key[:], c.tag, 3)
			got, err := acceptInit(&wire, c.secret)
			if c.ok != (err == nil) {
				t.Fatalf("accepted = %v, want %v (err %v)", err == nil, c.ok, err)
			}
			if c.ok && got.tag != c.tag {
				t.Fatalf("tag %x, want %x", got.tag, c.tag)
			}
		})
	}
}

func TestDCInitRoundTrip(t *testing.T) {
	for _, c := range []struct {
		tag [4]byte
		dc  int16
	}{{tagAbridgedBytes, 1}, {tagIntermediateBytes, -2}, {tagPaddedBytes, 4}, {tagPaddedBytes, -5}} {
		wire, encrypt, decrypt, err := newDCInit(rand.Reader, c.tag, c.dc)
		if err != nil {
			t.Fatal(err)
		}
		tag, dc, dcDecrypt, dcEncrypt := testServerInit(t, wire)
		if tag != c.tag || dc != c.dc {
			t.Fatalf("the DC read tag %x dc %d, want %x %d", tag, dc, c.tag, c.dc)
		}
		upload := []byte("to the DC")
		sealed := make([]byte, len(upload))
		encrypt.XORKeyStream(sealed, upload)
		dcDecrypt.XORKeyStream(sealed, sealed)
		if !bytes.Equal(sealed, upload) {
			t.Fatalf("the DC read %q", sealed)
		}
		download := []byte("from the DC")
		sealed = make([]byte, len(download))
		dcEncrypt.XORKeyStream(sealed, download)
		decrypt.XORKeyStream(sealed, sealed)
		if !bytes.Equal(sealed, download) {
			t.Fatalf("the proxy read %q", sealed)
		}
	}
}

func TestDCInitSkipsReservedFrames(t *testing.T) {
	good := bytes.Repeat([]byte{0x42}, 64)
	for _, prefix := range [][]byte{
		{0xef},
		[]byte("HEAD"), []byte("POST"), []byte("GET "), []byte("OPTI"),
		{0x16, 0x03, 0x01, 0x02},
		{0xdd, 0xdd, 0xdd, 0xdd},
		{0xee, 0xee, 0xee, 0xee},
		{0x42, 0x42, 0x42, 0x42, 0, 0, 0, 0},
	} {
		bad := append(append([]byte(nil), prefix...), good[len(prefix):]...)
		r := bytes.NewReader(append(bad, good...))
		wire, _, _, err := newDCInit(r, tagPaddedBytes, 2)
		if err != nil {
			t.Fatalf("prefix %x: %v", prefix, err)
		}
		if !bytes.Equal(wire[:56], good[:56]) {
			t.Fatalf("prefix %x: the reserved frame was sent: %x", prefix, wire[:8])
		}
	}
}
