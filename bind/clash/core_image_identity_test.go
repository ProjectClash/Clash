package clash

import (
	"runtime"
	"testing"
)

func TestTheCoreImageHasAnIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the identity is the Mach-O LC_UUID")
	}
	identity := coreImageIdentity()
	if len(identity) != 32 || identity != coreImageIdentity() {
		t.Fatalf("identity %q", identity)
	}
}
