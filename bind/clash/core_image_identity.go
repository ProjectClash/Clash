//go:build darwin && cgo

package clash

/*
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <string.h>

// clash_core_image_uuid copies the LC_UUID of the image this function is linked into -- the
// framework in an app, the test binary on a host -- and answers 1, or 0 when it has none.
static int clash_core_image_uuid(unsigned char out[16]) {
	Dl_info info;
	if (!dladdr((const void *)&clash_core_image_uuid, &info) || info.dli_fbase == NULL) return 0;
	const struct mach_header_64 *header = (const struct mach_header_64 *)info.dli_fbase;
	if (header->magic != MH_MAGIC_64) return 0;
	const struct load_command *command = (const struct load_command *)(header + 1);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (command->cmd == LC_UUID) {
			memcpy(out, ((const struct uuid_command *)command)->uuid, 16);
			return 1;
		}
		command = (const struct load_command *)((const char *)command + command->cmdsize);
	}
	return 0;
}
*/
import "C"

import (
	"encoding/hex"
	"unsafe"
)

func coreImageIdentity() string {
	var uuid [16]byte
	if C.clash_core_image_uuid((*C.uchar)(unsafe.Pointer(&uuid[0]))) == 0 {
		return ""
	}
	return hex.EncodeToString(uuid[:])
}
