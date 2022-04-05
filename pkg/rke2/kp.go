package rke2

import (
	"context"
	"sync"

	"github.com/rancher/rke2/pkg/config"
)

const kubeProxyChart = "rke2-kube-proxy"

func setKubeProxyDisabled() config.StartupHook {
	return func(ctx context.Context, wg *sync.WaitGroup, args config.StartupHookArgs) error {
		go func() {
			defer wg.Done()
			<-args.APIServerReady
			args.Skips[kubeProxyChart] = true
			args.Disables[kubeProxyChart] = true
		}()
		return nil
	}
}
