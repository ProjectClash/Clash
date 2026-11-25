package tun

import "syscall"

type goSpliceCall func(*goSocket, []goIOVector) (int, syscall.Errno)

func (e *goEngine) spliceVector(socket *goSocket, chain *goSlabChain, offset uint64, length int, call goSpliceCall) (int, syscall.Errno) {
	e.spliceSegments = chain.appendRuns(e.spliceSegments[:0], offset, length)
	e.spliceIovecs = goIovecsFromSegments(e.spliceIovecs, e.spliceSegments)
	defer func() {
		clear(e.spliceSegments)
		clear(e.spliceIovecs)
	}()
	return call(socket, e.spliceIovecs)
}
