//go:build darwin && cgo

package clash

/*
#include <sys/resource.h>

// clash_process_cpu_time_ns returns cumulative user + system CPU time for this
// process. RUSAGE_SELF covers every thread in the Network Extension process,
// including Go, cgo and Swift work. It intentionally excludes child processes.
static long long clash_process_cpu_time_ns() {
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) != 0) {
		return -1;
	}
	return ((long long)usage.ru_utime.tv_sec + (long long)usage.ru_stime.tv_sec) * 1000000000LL
		+ ((long long)usage.ru_utime.tv_usec + (long long)usage.ru_stime.tv_usec) * 1000LL;
}
*/
import "C"

func processCPUTimeNanoseconds() int64 {
	return int64(C.clash_process_cpu_time_ns())
}
