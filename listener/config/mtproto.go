package config

import "encoding/json"

type MTProtoServer struct {
	Listen string
	Secret string
	IPv6 bool
}

func (c MTProtoServer) String() string {
	b, _ := json.Marshal(c)
	return string(b)
}
