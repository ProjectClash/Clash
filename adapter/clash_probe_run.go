package adapter

import (
	"context"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)

func RunAsProbe(ctx context.Context, proxy C.Proxy, run func(ctx context.Context) error) error {
	if admit := urlTestAdmission.Load(); admit != nil {
		end, err := admit(ctx)
		if err != nil {
			return err
		}
		if end != nil {
			defer end()
		}
	}
	if finished := urlTestFinished.Load(); finished != nil {
		ctx = outbound.WithProbeDials(ctx)
		probed, _ := proxy.(*Proxy)
		defer finished(ctx, probed)
	}
	return run(dialer.WithDialKind(ctx, dialer.DialKindProbe))
}
