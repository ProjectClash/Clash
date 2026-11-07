package tun

import E "github.com/sagernet/sing/common/exceptions"

const WithGVisor = false

var ErrGVisorNotIncluded = E.New(`gVisor is not part of this copy of sing-tun; the listener runs gVisor from the other one`)

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	return nil, ErrGVisorNotIncluded
}

func NewMixed(
	options StackOptions,
) (Stack, error) {
	return nil, ErrGVisorNotIncluded
}
