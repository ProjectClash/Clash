package tun

func (s *Mipstack) ReleaseIdleBacking() int {
	if s.stack == nil {
		return 0
	}
	return s.stack.ReleaseIdleBacking()
}
