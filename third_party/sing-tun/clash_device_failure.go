package tun


type deviceFailurePolicy interface {
	readFailed(err error) (stop bool)
}

func FailDevice(device any, err error) bool {
	policy, ok := device.(deviceFailurePolicy)
	return ok && policy.readFailed(err)
}
