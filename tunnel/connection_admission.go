package tunnel

type TCPConnectionAdmission struct {
	Limit    int64
	Active   int64
	Rejected uint64
	Evicted  uint64
}
