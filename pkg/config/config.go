package config

import (
	"github.com/rancher/rke2/pkg/images"
	"github.com/urfave/cli"
)

type RootConfig struct {
	AuditPolicyFile              string
	CloudProviderConfig          string
	CloudProviderName            string
	Images                       images.ImageOverrideConfig
	KubeletPath                  string
	ControlPlaneResourceRequests string
	ControlPlaneResourceLimits   string
	ExtraMounts                  ExtraMounts
	ExtraEnv                     ExtraEnv
}

type ExtraMounts struct {
	KubeAPIServer          cli.StringSlice
	KubeScheduler          cli.StringSlice
	KubeControllerManager  cli.StringSlice
	KubeProxy              cli.StringSlice
	Etcd                   cli.StringSlice
	CloudControllerManager cli.StringSlice
}

type ExtraEnv struct {
	KubeAPIServer          cli.StringSlice
	KubeScheduler          cli.StringSlice
	KubeControllerManager  cli.StringSlice
	KubeProxy              cli.StringSlice
	Etcd                   cli.StringSlice
	CloudControllerManager cli.StringSlice
}
