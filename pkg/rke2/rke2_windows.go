//go:build windows
// +build windows

package rke2

// import (
// 	"fmt"
// 	"path/filepath"

// 	"github.com/pkg/errors"
// 	"github.com/rancher/rke2/pkg/agent/config"
// 	"github.com/rancher/rke2/pkg/cli/defaults"
// 	"github.com/rancher/rke2/pkg/cluster/managed"
// 	"github.com/rancher/rke2/pkg/etcd"
// 	"github.com/rancher/rke2/pkg/images"
// 	"github.com/rancher/rke2/pkg/pebinaryexecutor"
// 	"github.com/urfave/cli"
// )

// func (r *RKE2) initExecutor(clx *cli.Context, dataDir string) (*pebinaryexecutor.PEBinaryConfig, error) {
// 	// This flag will only be set on servers, on agents this is a no-op and the
// 	// resolver's default registry will get updated later when bootstrapping
// 	r.RootConfig.Images.SystemDefaultRegistry = clx.String("system-default-registry")
// 	resolver, err := images.NewResolver(r.RootConfig.Images)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if err := defaults.Set(clx, dataDir); err != nil {
// 		return nil, err
// 	}

// 	agentManifestsDir := filepath.Join(dataDir, "agent", config.DefaultPodManifestPath)
// 	agentImagesDir := filepath.Join(dataDir, "agent", "images")

// 	managed.RegisterDriver(&etcd.ETCD{})

// 	if clx.IsSet("cloud-provider-config") || clx.IsSet("cloud-provider-name") {
// 		if clx.IsSet("node-external-ip") {
// 			return nil, errors.New("can't set node-external-ip while using cloud provider")
// 		}
// 		r.ServerConfig.DisableCCM = true
// 	}
// 	var cpConfig *pebinaryexecutor.CloudProviderConfig
// 	if r.ServerConfig.CloudProviderConfig != "" && r.ServerConfig.CloudProviderName == "" {
// 		return nil, fmt.Errorf("--cloud-provider-config requires --cloud-provider-name to be provided")
// 	}
// 	if r.ServerConfig.CloudProviderName != "" {
// 		cpConfig = &pebinaryexecutor.CloudProviderConfig{
// 			Name: r.ServerConfig.CloudProviderName,
// 			Path: r.ServerConfig.CloudProviderConfig,
// 		}
// 	}

// 	if r.ServerConfig.KubeletPath == "" {
// 		r.ServerConfig.KubeletPath = "kubelet"
// 	}

// 	return &pebinaryexecutor.PEBinaryConfig{
// 		Resolver:        resolver,
// 		ImagesDir:       agentImagesDir,
// 		ManifestsDir:    agentManifestsDir,
// 		CISMode:         isCISMode(clx),
// 		CloudProvider:   cpConfig,
// 		DataDir:         dataDir,
// 		AuditPolicyFile: clx.String("audit-policy-file"),
// 		KubeletPath:     r.ServerConfig.KubeletPath,
// 		DisableETCD:     r.serverConfig.DisableETCD,
// 		IsServer:        r.IsServer,
// 	}, nil
// }
