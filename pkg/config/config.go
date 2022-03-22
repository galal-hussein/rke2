package config

import (
	"github.com/rancher/rke2/pkg/images"
	"github.com/urfave/cli"
)

const (
	CISProfile15           = "cis-1.5"
	CISProfile16           = "cis-1.6"
	defaultAuditPolicyFile = "/etc/rancher/rke2/audit-policy.yaml"
	containerdSock         = "/run/k3s/containerd/containerd.sock"
	KubeAPIServer          = "kube-apiserver"
	KubeScheduler          = "kube-scheduler"
	KubeControllerManager  = "kube-controller-manager"
	KubeProxy              = "kube-proxy"
	Etcd                   = "etcd"
	CloudControllerManager = "cloud-controller-manager"
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
