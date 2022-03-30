package templates

import (
	"github.com/rancher/wharfie/pkg/registries"

	"github.com/rancher/rke2/pkg/config"
)

type ContainerdRuntimeConfig struct {
	RuntimeType string
	BinaryName  string
}

type ContainerdConfig struct {
	NodeConfig            *config.Node
	DisableCgroup         bool
	IsRunningInUserNS     bool
	PrivateRegistryConfig *registries.Registry
	ExtraRuntimes         map[string]ContainerdRuntimeConfig
}
