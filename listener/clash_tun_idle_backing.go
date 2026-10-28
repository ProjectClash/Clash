package listener

func ReleaseTunIdleBacking() int {
	if !tunMux.TryLock() {
		return 0
	}
	defer tunMux.Unlock()
	return tunLister.ReleaseIdleBacking()
}
