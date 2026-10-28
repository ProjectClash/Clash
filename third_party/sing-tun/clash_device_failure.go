package tun


type deviceFailurePolicy interface {
	readFailed(err error) (stop bool)
}

func failDevice(device any, err error) bool {
	policy, ok := device.(deviceFailurePolicy)
	return ok && policy.readFailed(err)
}
