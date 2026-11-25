package clash

import gotun "github.com/sagernet/sing-tun"

func goStackRegionsKept() (regions int, bytes int64, notKept uint64) {
	return gotun.GoRegionsKept()
}
