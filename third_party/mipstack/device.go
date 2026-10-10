package mipstack

const deviceBatchSize = 64

func (s *Stack) MTU() (int, error) { return s.network.Load().mtu, nil }

func (s *Stack) Name() (string, error) { return "mihomo IP stack", nil }

func (s *Stack) BatchSize() int { return deviceBatchSize }
