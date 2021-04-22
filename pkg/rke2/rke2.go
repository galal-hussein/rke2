package rke2

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rancher/rke2/pkg/controllers/cisnetworkpolicy"
	"github.com/sirupsen/logrus"

	"github.com/rancher/k3s/pkg/agent/config"
	"github.com/rancher/k3s/pkg/cli/agent"
	"github.com/rancher/k3s/pkg/cli/cmds"
	"github.com/rancher/k3s/pkg/cli/etcdsnapshot"
	"github.com/rancher/k3s/pkg/cli/server"
	"github.com/rancher/k3s/pkg/cluster/managed"
	"github.com/rancher/k3s/pkg/daemons/executor"
	"github.com/rancher/k3s/pkg/etcd"
	rawServer "github.com/rancher/k3s/pkg/server"
	"github.com/rancher/rke2/pkg/bootstrap"
	"github.com/rancher/rke2/pkg/cli/defaults"
	"github.com/rancher/rke2/pkg/images"
	"github.com/rancher/rke2/pkg/podexecutor"
	"github.com/urfave/cli"
)

type Config struct {
	CloudProviderName   string
	CloudProviderConfig string
	AuditPolicyFile     string
	KubeletPath         string
	Images              images.ImageOverrideConfig
}

var cisMode bool

const (
	CISProfile15           = "cis-1.5"
	CISProfile16           = "cis-1.6"
	defaultAuditPolicyFile = "/etc/rancher/rke2/audit-policy.yaml"
	defaultPodManifestPath = "pod-manifests"
)

func Server(clx *cli.Context, cfg Config) error {
	if err := setup(clx, cfg); err != nil {
		return err
	}

	if err := clx.Set("secrets-encryption", "true"); err != nil {
		return err
	}

	// Disable all disableable k3s packaged components. In addition to manifests,
	// this also disables several integrated controllers.
	disableItems := strings.Split(cmds.DisableItems, ",")
	for _, item := range disableItems {
		if err := clx.Set("disable", strings.TrimSpace(item)); err != nil {
			return err
		}
	}

	cmds.ServerConfig.StartupHooks = append(cmds.ServerConfig.StartupHooks,
		setPSPs(),
		setNetworkPolicies(),
		setClusterRoles(),
	)

	var leaderControllers rawServer.CustomControllers

	if cisMode {
		leaderControllers = append(leaderControllers, cisnetworkpolicy.CISNetworkPolicyController)
	}

	return server.RunWithControllers(clx, leaderControllers, rawServer.CustomControllers{})
}

func Agent(clx *cli.Context, cfg Config) error {
	if err := setup(clx, cfg); err != nil {
		return err
	}
	return agent.Run(clx)
}

func EtcdSnapshot(clx *cli.Context, cfg Config) error {
	cmds.ServerConfig.DatastoreEndpoint = "etcd"
	return etcdsnapshot.Run(clx)
}

func setup(clx *cli.Context, cfg Config) error {
	profile := clx.String("profile")
	cisMode = profile == CISProfile15 || profile == CISProfile16
	dataDir := clx.String("data-dir")
	privateRegistry := clx.String("private-registry")
	disableETCD := clx.Bool("disable-etcd")
	disableScheduler := clx.Bool("disable-scheduler")
	disableAPIServer := clx.Bool("disable-api-server")
	disableControllerManager := clx.Bool("disable-controller-manager")

	auditPolicyFile := clx.String("audit-policy-file")
	if auditPolicyFile == "" {
		auditPolicyFile = defaultAuditPolicyFile
	}

	resolver, err := images.NewResolver(cfg.Images)
	if err != nil {
		return err
	}

	pauseImage, err := resolver.GetReference(images.Pause)
	if err != nil {
		return err
	}

	if err := defaults.Set(clx, pauseImage, dataDir); err != nil {
		return err
	}

	// If system-default-registry is set, add the same value to airgap-extra-registry so that images
	// imported from tarballs are tagged to appear to come from the same registry.
	if cfg.Images.SystemDefaultRegistry != "" {
		clx.Set("airgap-extra-registry", cfg.Images.SystemDefaultRegistry)
	}

	execPath, err := bootstrap.Stage(dataDir, privateRegistry, resolver)
	if err != nil {
		return err
	}

	if err := os.Setenv("PATH", execPath+":"+os.Getenv("PATH")); err != nil {
		return err
	}

	agentManifestsDir := filepath.Join(dataDir, "agent", config.DefaultPodManifestPath)
	agentImagesDir := filepath.Join(dataDir, "agent", "images")

	managed.RegisterDriver(&etcd.ETCD{})

	if clx.IsSet("cloud-provider-config") || clx.IsSet("cloud-provider-name") {
		if clx.IsSet("node-external-ip") {
			return errors.New("can't set node-external-ip while using cloud provider")
		}
		cmds.ServerConfig.DisableCCM = true
	}
	var cpConfig *podexecutor.CloudProviderConfig
	if cfg.CloudProviderConfig != "" && cfg.CloudProviderName == "" {
		return fmt.Errorf("--cloud-provider-config requires --cloud-provider-name to be provided")
	}
	if cfg.CloudProviderName != "" {
		cpConfig = &podexecutor.CloudProviderConfig{
			Name: cfg.CloudProviderName,
			Path: cfg.CloudProviderConfig,
		}
	}

	if cfg.KubeletPath == "" {
		cfg.KubeletPath = "kubelet"
	}

	sp := podexecutor.StaticPodConfig{
		Resolver:        resolver,
		ImagesDir:       agentImagesDir,
		ManifestsDir:    agentManifestsDir,
		CISMode:         cisMode,
		CloudProvider:   cpConfig,
		DataDir:         dataDir,
		AuditPolicyFile: auditPolicyFile,
		KubeletPath:     cfg.KubeletPath,
		DisableETCD:     disableETCD,
	}
	executor.Set(&sp)

	disabledItems := map[string]bool{
		"kube-apiserver":          disableAPIServer,
		"kube-scheduler":          disableScheduler,
		"kube-controller-manager": disableControllerManager,
		"etcd":                    disableETCD,
	}
	return removeOldPodManifests(dataDir, disabledItems)
}

func podManifestsDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", defaultPodManifestPath)
}

func removeOldPodManifests(dataDir string, disabledItems map[string]bool) error {
	var kubeletStandAlone bool
	for component, disabled := range disabledItems {
		if disabled {
			manifestName := filepath.Join(podManifestsDir(dataDir), component+".yaml")
			if _, err := os.Stat(manifestName); err == nil {
				kubeletStandAlone = true
				if err := os.Remove(manifestName); err != nil {
					return err
				}
			}
		}
	}
	if kubeletStandAlone {
		// starting containerd first then kubelet
		tmpAddress := filepath.Join(os.TempDir(), "containerd.sock")
		args := []string{
			"-a", tmpAddress,
			"--root", filepath.Join(dataDir, "agent", "containerd"),
		}
		containerdCmd := exec.Command("containerd", args...)
		containerdCmd.Stdout = os.Stdout
		containerdCmd.Stderr = os.Stderr
		containerdErr := make(chan error)

		// starting kubelet in standalone mode to delete old static pods
		args = []string{
			"--fail-swap-on=false",
			"--container-runtime=remote",
			"--containerd=" + tmpAddress,
			"--container-runtime-endpoint=unix://" + tmpAddress,
			"--pod-manifest-path=" + podManifestsDir(dataDir),
		}
		kubelet := exec.Command("kubelet", args...)
		kubelet.Stdout = os.Stdout
		kubelet.Stderr = os.Stderr
		kubeletErr := make(chan error)
		go func() {
			select {
			case err := <-kubeletErr:
				logrus.Infof("kubelet Exited: %v", err)
			case err := <-containerdErr:
				logrus.Infof("Containerd Exited: %v", err)
			case <-time.After(2 * time.Minute):
				kubelet.Process.Kill()
				containerdCmd.Process.Kill()
			}

		}()
		go func() {
			containerdErr <- containerdCmd.Run()
		}()
		go func() {
			kubeletErr <- kubelet.Run()
		}()
	}

	return nil
}
