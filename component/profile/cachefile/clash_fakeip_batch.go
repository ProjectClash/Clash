package cachefile

import (
	"net/netip"

	"github.com/metacubex/bbolt"
)

type FakeIPOpKind uint8

const (
	FakeIPPutByHost FakeIPOpKind = iota + 1
	FakeIPPutByIP
	FakeIPDelByIP
)

type FakeIPOp struct {
	Kind FakeIPOpKind
	Host string
	IP   netip.Addr
}

type FakeIPStoreKey struct {
	db     *bbolt.DB
	bucket string
}

func (c *FakeIpStore) Key() FakeIPStoreKey {
	return FakeIPStoreKey{c.DB, string(c.bucketName)}
}

func (c *FakeIpStore) Apply(ops []FakeIPOp) error {
	if c.DB == nil || len(ops) == 0 {
		return nil
	}
	return c.DB.Update(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}
		for _, op := range ops {
			switch op.Kind {
			case FakeIPPutByHost:
				err = bucket.Put([]byte(op.Host), op.IP.AsSlice())
			case FakeIPPutByIP:
				err = bucket.Put(op.IP.AsSlice(), []byte(op.Host))
			case FakeIPDelByIP:
				addr := op.IP.AsSlice()
				host := bucket.Get(addr)
				err = bucket.Delete(addr)
				if err == nil && len(host) > 0 {
					err = bucket.Delete(append([]byte(nil), host...))
				}
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}
