package provider

import "time"

func (rp *ruleSetProvider) LoadDetached(buf []byte, updatedAt time.Time) error {
	strategy, err := rp.Fetcher.Parse(buf)
	if err != nil {
		return err
	}
	rp.strategy.Store(strategy)
	rp.Fetcher.SetUpdatedAt(updatedAt)
	return nil
}
