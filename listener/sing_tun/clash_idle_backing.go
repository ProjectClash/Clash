package sing_tun

func (l *Listener) ReleaseIdleBacking() int {
	if l == nil {
		return 0
	}
	if releaser, ok := l.tunStack.(interface{ ReleaseIdleBacking() int }); ok {
		return releaser.ReleaseIdleBacking()
	}
	return 0
}
