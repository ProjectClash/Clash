package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

const mdnsSliceMarker = "too many queries in flight"

func verifyMDNSClientInXCFramework(xcframework string) error {
	sliceDirs, err := xcframeworkSliceDirs(xcframework)
	if err != nil {
		return err
	}
	checked := 0
	for _, sliceDir := range sliceDirs {
		slice := filepath.Base(sliceDir)
		binary, err := appleSliceBinary(sliceDir)
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(binary)
		if err != nil {
			return fmt.Errorf("read %s: %w", binary, err)
		}
		if !bytes.Contains(contents, []byte(mdnsSliceMarker)) {
			return fmt.Errorf("slice %s does not carry the multicast-DNS client (marker %q missing): "+
				"the platform test in installLocalZoneResolver excluded this slice and the linker dropped it. "+
				"Decide platforms by build tag, never by runtime.GOOS -- GOOS is \"ios\" where the tag is \"darwin\"",
				slice, mdnsSliceMarker)
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no slices found under %s", xcframework)
	}
	fmt.Fprintf(os.Stderr, "build_libbox: multicast-DNS client present in %d slice(s)\n", checked)
	return nil
}
