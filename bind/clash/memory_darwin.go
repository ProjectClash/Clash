//go:build darwin && cgo

package clash

/*
#include <dispatch/dispatch.h>
#include <limits.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#include <os/proc.h>
#endif

// clash_phys_footprint returns this task's phys_footprint — the exact number
// iOS jetsam uses to decide killing the NE. -1 on failure.
static long long clash_phys_footprint() {
	task_vm_info_data_t info;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
	if (kr != KERN_SUCCESS) return -1;
	return (long long)info.phys_footprint;
}

// os_proc_available_memory is iOS-only. It is a point-in-time advisory
// snapshot and must be queried for every low-frequency diagnostic sample.
// Keep the macOS gomobile slice linkable by returning -1 there.
// os_proc_available_memory is declared in the SDK headers under TARGET_OS_IPHONE, but the
// SYMBOL exists in libSystem on macOS too. Gating on the compile-time macro therefore returned
// -1 on every macOS build, which made resolveThresholdMode pick "none" and left the whole
// memory threshold machine inert on the platform it was ported for.
//
// Upstream resolves it at runtime instead (sing's common/memory/memory_darwin.go uses
// dlsym(RTLD_DEFAULT, "os_proc_available_memory") and reports separately whether it resolved),
// which is both the portable answer and the reason macOS works there. Copied.
//
// The quantity is this PROCESS's remaining headroom, not the machine's free memory. That
// matters for reading the thresholds: upstream's available-mode margins are scaled off our own
// footprint precisely because both sides of the comparison are per-process.
typedef size_t (*clash_proc_available_memory_func)(void);
static int clash_available_memory_resolved = 0;
static clash_proc_available_memory_func clash_available_memory_fn = NULL;

static void clash_resolve_available_memory() {
	if (!clash_available_memory_resolved) {
		clash_available_memory_fn =
			(clash_proc_available_memory_func)dlsym(RTLD_DEFAULT, "os_proc_available_memory");
		clash_available_memory_resolved = 1;
	}
}

static long long clash_available_memory() {
	clash_resolve_available_memory();
	if (!clash_available_memory_fn) {
		return -1;
	}
	size_t available = clash_available_memory_fn();
	if (available > LLONG_MAX) return LLONG_MAX;
	return (long long)available;
}

extern void clashMemoryPressureCallback(unsigned long status);

static dispatch_source_t clashMemoryPressureSource;

static void clashStartMemoryPressureMonitor() {
	if (clashMemoryPressureSource) {
		return;
	}
	clashMemoryPressureSource = dispatch_source_create(
		DISPATCH_SOURCE_TYPE_MEMORYPRESSURE,
		0,
		DISPATCH_MEMORYPRESSURE_CRITICAL,
		dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0)
	);
	dispatch_source_set_event_handler(clashMemoryPressureSource, ^{
		unsigned long status = dispatch_source_get_data(clashMemoryPressureSource);
		clashMemoryPressureCallback(status);
	});
	dispatch_activate(clashMemoryPressureSource);
}
*/
import "C"

import "sync"

var memoryPressureOnce sync.Once

func startMemoryPressureMonitor() {
	memoryPressureOnce.Do(func() {
		C.clashStartMemoryPressureMonitor()
	})
}

//export clashMemoryPressureCallback
func clashMemoryPressureCallback(_ C.ulong) {
	handleMemoryPressure()
}

func physFootprint() int64 {
	return int64(C.clash_phys_footprint())
}

func availableMemory() int64 {
	return int64(C.clash_available_memory())
}
