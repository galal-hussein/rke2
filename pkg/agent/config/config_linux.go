//go:build linux
// +build linux

package config

import (
	"path/filepath"

	"github.com/rancher/rke2/pkg/config"
)

func applyContainerdStateAndAddress(nodeConfig *config.Node) {
	nodeConfig.Containerd.State = "/run/k3s/containerd"
	nodeConfig.Containerd.Address = filepath.Join(nodeConfig.Containerd.State, "containerd.sock")
}
