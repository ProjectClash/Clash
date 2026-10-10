package clash

import (
	"path/filepath"

	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
)

func armProviderCache() {
	pointProviderCacheAtHome()
	providerCache.consumeInflight()
}

func pointProviderCacheAtHome() {
	home := C.Path.HomeDir()
	providerCache.useHome(home)
	resource.SetDeferredFileDirectory(filepath.Join(home, ProviderRefreshDirectoryName))
}
