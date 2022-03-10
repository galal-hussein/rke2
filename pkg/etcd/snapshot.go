package etcd

import (
	"github.com/rancher/k3s/pkg/cli/etcdsnapshot"
	"github.com/rancher/rke2/pkg/cli/cmds"
	"github.com/urfave/cli"
)

func EtcdSnapshot(clx *cli.Context, cfg Config) error {
	cmds.ServerConfig.DatastoreEndpoint = "etcd"
	return etcdsnapshot.Run(clx)
}
