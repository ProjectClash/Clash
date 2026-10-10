//go:build !darwin

package clash

import (
	"context"
	"errors"

	D "github.com/miekg/dns"
)

const mdnsSupported = false

func exchangeMulticastDNS(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errors.New("mdns: mDNSResponder is only available on Darwin")
}
