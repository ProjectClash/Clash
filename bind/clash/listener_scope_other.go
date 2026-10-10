//go:build !darwin

package clash

func installListenerScopeHooks(underNetworkExtension bool) {}

func scheduleLANReconcile() {}
