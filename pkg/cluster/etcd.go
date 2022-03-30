package cluster

import (
	"github.com/rancher/rke2/pkg/cluster/managed"
	"github.com/rancher/rke2/pkg/etcd"
)

func init() {
	managed.RegisterDriver(etcd.NewETCD())
}
