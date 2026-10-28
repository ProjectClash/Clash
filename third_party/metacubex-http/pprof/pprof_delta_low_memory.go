//go:build with_low_memory

package pprof

import (
	"runtime/pprof"

	"github.com/metacubex/http"
)

const deltaProfilesServed = false

func (name handler) serveDeltaProfile(w http.ResponseWriter, r *http.Request, p *pprof.Profile, secStr string) {
	serveError(w, http.StatusBadRequest, `"seconds" parameter is not supported in this build`)
}
