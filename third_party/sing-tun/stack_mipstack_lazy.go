package tun

import (
	"context"
	"errors"
	"net"

	mips "github.com/metacubex/mipstack"
)

type mipsDeferredRequest struct{ request *mips.TCPForwarderRequest }

func (r mipsDeferredRequest) accept(ctx context.Context) (net.Conn, error) {
	conn, err := r.request.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (r mipsDeferredRequest) reject() error {
	err := r.request.Reject()
	if err != nil && !errors.Is(err, mips.ErrForwarderRequestCompleted) {
		return err
	}
	return nil
}

func (r mipsDeferredRequest) done() <-chan struct{} { return r.request.Done() }

func newMipsLazyConn(ctx context.Context, request *mips.TCPForwarderRequest, stackDone <-chan struct{}, local, remote net.Addr) *deferredConn {
	return newDeferredConn(ctx, mipsDeferredRequest{request: request}, stackDone, local, remote)
}
