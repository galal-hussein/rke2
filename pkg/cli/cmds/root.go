package cmds

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/rancher/rke2/pkg/config"
	"github.com/rancher/rke2/pkg/configfilearg"
	"github.com/rancher/rke2/pkg/images"
	"github.com/rancher/rke2/pkg/log"
	"github.com/rancher/rke2/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	appName = filepath.Base(os.Args[0])

	RootConfig    = config.RootConfig{}
	DefaultParser = configfilearg.DefaultParser(map[string][]cli.Flag{"server": ServerFlags, "agent": AgentFlags})

	commonFlag = []cli.Flag{
		&cli.StringFlag{
			Name:        images.KubeAPIServer,
			Usage:       "(image) Override image to use for kube-apiserver",
			EnvVar:      "RKE2_KUBE_APISERVER_IMAGE",
			Destination: &RootConfig.Images.KubeAPIServer,
		},
		&cli.StringFlag{
			Name:        images.KubeControllerManager,
			Usage:       "(image) Override image to use for kube-controller-manager",
			EnvVar:      "RKE2_KUBE_CONTROLLER_MANAGER_IMAGE",
			Destination: &RootConfig.Images.KubeControllerManager,
		},
		&cli.StringFlag{
			Name:        images.KubeProxy,
			Usage:       "(image) Override image to use for kube-proxy",
			EnvVar:      "RKE2_KUBE_PROXY_IMAGE",
			Destination: &RootConfig.Images.KubeProxy,
		},
		&cli.StringFlag{
			Name:        images.KubeScheduler,
			Usage:       "(image) Override image to use for kube-scheduler",
			EnvVar:      "RKE2_KUBE_SCHEDULER_IMAGE",
			Destination: &RootConfig.Images.KubeScheduler,
		},
		&cli.StringFlag{
			Name:        images.Pause,
			Usage:       "(image) Override image to use for pause",
			EnvVar:      "RKE2_PAUSE_IMAGE",
			Destination: &RootConfig.Images.Pause,
		},
		&cli.StringFlag{
			Name:        images.Runtime,
			Usage:       "(image) Override image to use for runtime binaries (containerd, kubectl, crictl, etc)",
			EnvVar:      "RKE2_RUNTIME_IMAGE",
			Destination: &RootConfig.Images.Runtime,
		},
		&cli.StringFlag{
			Name:        images.ETCD,
			Usage:       "(image) Override image to use for etcd",
			EnvVar:      "RKE2_ETCD_IMAGE",
			Destination: &RootConfig.Images.ETCD,
		},
		&cli.StringFlag{
			Name:        "kubelet-path",
			Usage:       "(experimental/agent) Override kubelet binary path",
			EnvVar:      "RKE2_KUBELET_PATH",
			Destination: &RootConfig.KubeletPath,
		},
		&cli.StringFlag{
			Name:        "cloud-provider-name",
			Usage:       "(cloud provider) Cloud provider name",
			EnvVar:      "RKE2_CLOUD_PROVIDER_NAME",
			Destination: &RootConfig.CloudProviderName,
		},
		&cli.StringFlag{
			Name:        "cloud-provider-config",
			Usage:       "(cloud provider) Cloud provider configuration file path",
			EnvVar:      "RKE2_CLOUD_PROVIDER_CONFIG",
			Destination: &RootConfig.CloudProviderConfig,
		},
		&cli.StringFlag{
			Name:   "profile",
			Usage:  "(security) Validate system configuration against the selected benchmark (valid items: " + config.CISProfile15 + ", " + config.CISProfile16 + " )",
			EnvVar: "RKE2_CIS_PROFILE",
		},
		&cli.StringFlag{
			Name:        "audit-policy-file",
			Usage:       "(security) Path to the file that defines the audit policy configuration",
			EnvVar:      "RKE2_AUDIT_POLICY_FILE",
			Destination: &RootConfig.AuditPolicyFile,
		},
		&cli.StringFlag{
			Name:        "control-plane-resource-requests",
			Usage:       "(components) Control Plane resource requests",
			EnvVar:      "RKE2_CONTROL_PLANE_RESOURCE_REQUESTS",
			Destination: &RootConfig.ControlPlaneResourceRequests,
		},
		&cli.StringFlag{
			Name:        "control-plane-resource-limits",
			Usage:       "(components) Control Plane resource limits",
			EnvVar:      "RKE2_CONTROL_PLANE_RESOURCE_LIMITS",
			Destination: &RootConfig.ControlPlaneResourceLimits,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeAPIServer + "-extra-mount",
			Usage:  "(components) " + config.KubeAPIServer + " extra volume mounts",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeAPIServer, "-", "_")) + "_EXTRA_MOUNT",
			Value:  &RootConfig.ExtraMounts.KubeAPIServer,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeScheduler + "-extra-mount",
			Usage:  "(components) " + config.KubeScheduler + " extra volume mounts",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeScheduler, "-", "_")) + "_EXTRA_MOUNT",
			Value:  &RootConfig.ExtraMounts.KubeScheduler,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeControllerManager + "-extra-mount",
			Usage:  "(components) " + config.KubeControllerManager + " extra volume mounts",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeControllerManager, "-", "_")) + "_EXTRA_MOUNT",
			Value:  &RootConfig.ExtraMounts.KubeControllerManager,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeProxy + "-extra-mount",
			Usage:  "(components) " + config.KubeProxy + " extra volume mounts",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeProxy, "-", "_")) + "_EXTRA_MOUNT",
			Value:  &RootConfig.ExtraMounts.KubeProxy,
		},
		&cli.StringSliceFlag{
			Name:   config.Etcd + "-extra-mount",
			Usage:  "(components) " + config.Etcd + " extra volume mounts",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.Etcd, "-", "_")) + "_EXTRA_MOUNT",
			Value:  &RootConfig.ExtraMounts.Etcd,
		},
		&cli.StringSliceFlag{
			Name:   config.CloudControllerManager + "-extra-mount",
			Usage:  "(components) " + config.CloudControllerManager + " extra volume mounts",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.CloudControllerManager, "-", "_")) + "_EXTRA_MOUNT",
			Value:  &RootConfig.ExtraMounts.CloudControllerManager,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeAPIServer + "-extra-env",
			Usage:  "(components) " + config.KubeAPIServer + " extra environment variables",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeAPIServer, "-", "_")) + "_EXTRA_ENV",
			Value:  &RootConfig.ExtraEnv.KubeAPIServer,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeScheduler + "-extra-env",
			Usage:  "(components) " + config.KubeScheduler + " extra environment variables",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeScheduler, "-", "_")) + "_EXTRA_ENV",
			Value:  &RootConfig.ExtraEnv.KubeScheduler,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeControllerManager + "-extra-env",
			Usage:  "(components) " + config.KubeControllerManager + " extra environment variables",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeControllerManager, "-", "_")) + "_EXTRA_ENV",
			Value:  &RootConfig.ExtraEnv.KubeControllerManager,
		},
		&cli.StringSliceFlag{
			Name:   config.KubeProxy + "-extra-env",
			Usage:  "(components) " + config.KubeProxy + " extra environment variables",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.KubeProxy, "-", "_")) + "_EXTRA_ENV",
			Value:  &RootConfig.ExtraEnv.KubeProxy,
		},
		&cli.StringSliceFlag{
			Name:   config.Etcd + "-extra-env",
			Usage:  "(components) " + config.Etcd + " extra environment variables",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.Etcd, "-", "_")) + "_EXTRA_ENV",
			Value:  &RootConfig.ExtraEnv.Etcd,
		},
		&cli.StringSliceFlag{
			Name:   config.CloudControllerManager + "-extra-env",
			Usage:  "(components) " + config.CloudControllerManager + " extra environment variables",
			EnvVar: "RKE2_" + strings.ToUpper(strings.ReplaceAll(config.CloudControllerManager, "-", "_")) + "_EXTRA_ENV",
			Value:  &RootConfig.ExtraEnv.CloudControllerManager,
		},
	}
)

const (
	protectKernelDefaultsFlagName = "protect-kernel-defaults"
)

type CLIRole int64

const (
	DefaultPauseImage          = "rancher/mirrored-pause:3.6"
	DefaultSnapshotter         = "overlayfs"
	AgentRole          CLIRole = iota
	ServerRole
)

func init() {
	// hack - force "file,dns" lookup order if go dns is used
	if os.Getenv("RES_OPTIONS") == "" {
		os.Setenv("RES_OPTIONS", " ")
	}
}

// kernelRuntimeParameters contains the names and values
// of the expected values from the Rancher Hardening guide
// for CIS 1.5 compliance.
var kernelRuntimeParameters = map[string]int{
	"vm.overcommit_memory": 1,
	"vm.panic_on_oom":      0,
	"kernel.panic":         10,
	"kernel.panic_on_oops": 1,
}

// sysctl retrieves the value of the given sysctl.
func sysctl(s string) (int, error) {
	s = strings.ReplaceAll(s, ".", "/")
	v, err := ioutil.ReadFile("/proc/sys/" + s)
	if err != nil {
		return 0, err
	}
	if len(v) < 2 || v[len(v)-1] != '\n' {
		return 0, fmt.Errorf("invalid contents: %s", s)
	}
	return strconv.Atoi(strings.Replace(string(v), "\n", "", -1))
}

// cisErrors holds errors reported during
// the start-up routine that checks for
// CIS compliance.
type cisErrors []error

// Error provides a string representation of the
// cisErrors type and satisfies the Error interface.
func (c cisErrors) Error() string {
	var err strings.Builder
	for _, e := range c {
		err.WriteString(e.Error() + "\n")
	}
	return err.String()
}

// validateCISReqs checks if the system is in compliance
// with CIS 1.5 benchmark requirements. The nodeType string
// is used to filter out tests that may only be relevant to servers
// or agents.
func validateCISReqs(role CLIRole) error {
	ce := make(cisErrors, 0)

	// etcd user only needs to exist on servers
	if role == ServerRole {
		if _, err := user.Lookup("etcd"); err != nil {
			ce = append(ce, errors.Wrap(err, "missing required"))
		}
		if _, err := user.LookupGroup("etcd"); err != nil {
			ce = append(ce, errors.Wrap(err, "missing required"))
		}
	}

	for kp, pv := range kernelRuntimeParameters {
		cv, err := sysctl(kp)
		if err != nil {
			// Fail immediately if we cannot retrieve the current value,
			// since it is unlikely that we will be able to retrieve others
			// if this one failed.
			logrus.Fatal(err)
		}
		if cv != pv {
			ce = append(ce, fmt.Errorf("invalid kernel parameter value %s=%d - expected %d", kp, cv, pv))
		}
	}
	if len(ce) != 0 {
		return ce
	}
	return nil
}

// setCISFlags validates and sets any CLI flags necessary to ensure
// compliance with the profile.
func setCISFlags(clx *cli.Context) error {
	// If the user has specifically set this to false, raise an error
	if clx.IsSet(protectKernelDefaultsFlagName) && !clx.Bool(protectKernelDefaultsFlagName) {
		return fmt.Errorf("--%s must be true when using --profile=%s", protectKernelDefaultsFlagName, clx.String("profile"))
	}
	return clx.Set(protectKernelDefaultsFlagName, "true")
}

func validateProfile(clx *cli.Context, role CLIRole) {
	switch clx.String("profile") {
	case config.CISProfile15, config.CISProfile16:
		if err := validateCISReqs(role); err != nil {
			logrus.Fatal(err)
		}
		if err := setCISFlags(clx); err != nil {
			logrus.Fatal(err)
		}
	case "":
		logrus.Warn("not running in CIS mode")
	default:
		logrus.Fatal("invalid value provided for --profile flag")
	}
}

func validateCloudProviderName(role CLIRole) {
	cloudProviderDisables := map[string][]string{
		"rancher-vsphere": {"rancher-vsphere-cpi", "rancher-vsphere-csi"},
		"harvester":       {"harvester-cloud-provider", "harvester-csi-driver"},
	}

	for providerName, disables := range cloudProviderDisables {
		if providerName == RootConfig.CloudProviderName {
			RootConfig.CloudProviderName = "external"
			if role == ServerRole {
				ServerConfig.DisableCCM = true
			}
		} else {
			if role == ServerRole {
				ServerConfig.Disables = map[string]bool{}
				for _, disable := range disables {
					ServerConfig.Disables[disable] = true
				}
			}
		}
	}
}

func NewApp() *cli.App {
	app := cli.NewApp()
	app.Name = appName
	app.Usage = "Rancher Kubernetes Engine 2"
	app.Version = fmt.Sprintf("%s (%s)", version.Version, version.GitCommit)
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("%s version %s\n", app.Name, app.Version)
		fmt.Printf("go version %s\n", runtime.Version())
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "Turn on debug logs",
			Destination: &log.LogConfig.Debug,
			EnvVar:      "RKE2_DEBUG",
		},
	}

	app.Before = func(clx *cli.Context) error {
		if log.LogConfig.Debug {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}

	return app
}
