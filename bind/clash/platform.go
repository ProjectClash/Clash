package clash

type PlatformInterface interface {
	WriteLog(message string)

	OpenTun(options TunOptions) (int32, error)

	UsePlatformAutoDetectInterfaceControl() bool

	AutoDetectInterfaceControl(fd int32) error

	StartDefaultInterfaceMonitor(listener InterfaceUpdateListener) error
	CloseDefaultInterfaceMonitor(listener InterfaceUpdateListener) error

	GetInterfaces() (NetworkInterfaceIterator, error)

	UnderNetworkExtension() bool
}

type InterfaceUpdateListener interface {
	UpdateDefaultInterface(interfaceName string, interfaceIndex int32, isExpensive bool, isConstrained bool, supportsIPv4 bool, supportsIPv6 bool)
}
