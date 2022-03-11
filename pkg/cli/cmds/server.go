package cmds

import (
	"strings"
	"time"

	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/version"
	"github.com/rancher/rke2/pkg/config"
	"github.com/rancher/rke2/pkg/rke2"
	"github.com/rancher/wrangler/pkg/slice"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	rke2Path = "/var/lib/rancher/rke2"
)

var (
	DisableItems = []string{"rke2-coredns", "rke2-ingress-nginx", "rke2-metrics-server"}
	CNIItems     = []string{"calico", "canal", "cilium"}

	ServerConfig = config.Server{}

	serverFlag = []cli.Flag{
		&cli.StringSliceFlag{
			Name:   "cni",
			Usage:  "(networking) CNI Plugins to deploy, one of none, " + strings.Join(CNIItems, ", ") + "; optionally with multus as the first value to enable the multus meta-plugin (default: canal)",
			EnvVar: "RKE2_CNI",
		},
	}

	ConfigFlag = cli.StringFlag{
		Name:   "config,c",
		Usage:  "(config) Load configuration from `FILE`",
		EnvVar: version.ProgramUpper + "_CONFIG_FILE",
		Value:  "/etc/rancher/" + version.Program + "/config.yaml",
	}
	DataDirFlag = cli.StringFlag{
		Name:        "data-dir,d",
		Usage:       "(data) Folder to hold state default /var/lib/rancher/" + version.Program,
		Destination: &cmds.ServerConfig.DataDir,
		Value:       rke2Path,
	}
	ServerToken = cli.StringFlag{
		Name:        "token,t",
		Usage:       "(cluster) Shared secret used to join a server or agent to a cluster",
		Destination: &cmds.ServerConfig.Token,
		EnvVar:      version.ProgramUpper + "_TOKEN",
	}
	ClusterCIDR = cli.StringSliceFlag{
		Name:  "cluster-cidr",
		Usage: "(networking) IPv4/IPv6 network CIDRs to use for pod IPs (default: 10.42.0.0/16)",
		Value: &cmds.ServerConfig.ClusterCIDR,
	}
	ServiceCIDR = cli.StringSliceFlag{
		Name:  "service-cidr",
		Usage: "(networking) IPv4/IPv6 network CIDRs to use for service IPs (default: 10.43.0.0/16)",
		Value: &cmds.ServerConfig.ServiceCIDR,
	}
	ServiceNodePortRange = cli.StringFlag{
		Name:        "service-node-port-range",
		Usage:       "(networking) Port range to reserve for services with NodePort visibility",
		Destination: &cmds.ServerConfig.ServiceNodePortRange,
		Value:       "30000-32767",
	}
	ClusterDNS = cli.StringSliceFlag{
		Name:  "cluster-dns",
		Usage: "(networking) IPv4 Cluster IP for coredns service. Should be in your service-cidr range (default: 10.43.0.10)",
		Value: &cmds.ServerConfig.ClusterDNS,
	}
	ClusterDomain = cli.StringFlag{
		Name:        "cluster-domain",
		Usage:       "(networking) Cluster Domain",
		Destination: &cmds.ServerConfig.ClusterDomain,
		Value:       "cluster.local",
	}
	ExtraAPIArgs = cli.StringSliceFlag{
		Name:  "kube-apiserver-arg",
		Usage: "(flags) Customized flag for kube-apiserver process",
		Value: &cmds.ServerConfig.ExtraAPIArgs,
	}
	ExtraEtcdArgs = cli.StringSliceFlag{
		Name:  "etcd-arg",
		Usage: "(flags) Customized flag for etcd process",
		Value: &cmds.ServerConfig.ExtraEtcdArgs,
	}
	ExtraSchedulerArgs = cli.StringSliceFlag{
		Name:  "kube-scheduler-arg",
		Usage: "(flags) Customized flag for kube-scheduler process",
		Value: &cmds.ServerConfig.ExtraSchedulerArgs,
	}
	ExtraControllerArgs = cli.StringSliceFlag{
		Name:  "kube-controller-manager-arg",
		Usage: "(flags) Customized flag for kube-controller-manager process",
		Value: &cmds.ServerConfig.ExtraControllerArgs,
	}
)

var ServerFlags = []cli.Flag{
	ConfigFlag,
	DebugFlag,
	VLevel,
	VModule,
	LogFile,
	AlsoLogToStderr,
	cli.StringFlag{
		Name:        "bind-address",
		Usage:       "(listener) " + version.Program + " bind address (default: 0.0.0.0)",
		Destination: &cmds.ServerConfig.BindAddress,
	},
	cli.StringFlag{
		Name:        "advertise-address",
		Usage:       "(listener) IPv4 address that apiserver uses to advertise to members of the cluster (default: node-external-ip/node-ip)",
		Destination: &cmds.ServerConfig.AdvertiseIP,
	},
	cli.StringSliceFlag{
		Name:  "tls-san",
		Usage: "(listener) Add additional hostnames or IPv4/IPv6 addresses as Subject Alternative Names on the server TLS cert",
		Value: &cmds.ServerConfig.TLSSan,
	},
	DataDirFlag,
	ClusterCIDR,
	ServiceCIDR,
	ServiceNodePortRange,
	ClusterDNS,
	ClusterDomain,
	ServerToken,
	cli.StringFlag{
		Name:        "token-file",
		Usage:       "(cluster) File containing the cluster-secret/token",
		Destination: &cmds.ServerConfig.TokenFile,
		EnvVar:      version.ProgramUpper + "_TOKEN_FILE",
	},
	cli.StringFlag{
		Name:        "write-kubeconfig,o",
		Usage:       "(client) Write kubeconfig for admin client to this file",
		Destination: &cmds.ServerConfig.KubeConfigOutput,
		EnvVar:      version.ProgramUpper + "_KUBECONFIG_OUTPUT",
	},
	cli.StringFlag{
		Name:        "write-kubeconfig-mode",
		Usage:       "(client) Write kubeconfig with this mode",
		Destination: &cmds.ServerConfig.KubeConfigMode,
		EnvVar:      version.ProgramUpper + "_KUBECONFIG_MODE",
	},
	ExtraAPIArgs,
	ExtraEtcdArgs,
	ExtraControllerArgs,
	ExtraSchedulerArgs,
	cli.StringSliceFlag{
		Name:  "kube-cloud-controller-manager-arg",
		Usage: "(flags) Customized flag for kube-cloud-controller-manager process",
		Value: &cmds.ServerConfig.ExtraCloudControllerArgs,
	},
	&cli.BoolFlag{
		Name:        "etcd-expose-metrics",
		Usage:       "(db) Expose etcd metrics to client interface. (Default false)",
		Destination: &cmds.ServerConfig.EtcdExposeMetrics,
	},
	&cli.BoolFlag{
		Name:        "etcd-disable-snapshots",
		Usage:       "(db) Disable automatic etcd snapshots",
		Destination: &cmds.ServerConfig.EtcdDisableSnapshots,
	},
	&cli.StringFlag{
		Name:        "etcd-snapshot-name",
		Usage:       "(db) Set the base name of etcd snapshots. Default: etcd-snapshot-<unix-timestamp>",
		Destination: &cmds.ServerConfig.EtcdSnapshotName,
		Value:       "etcd-snapshot",
	},
	&cli.StringFlag{
		Name:        "etcd-snapshot-schedule-cron",
		Usage:       "(db) Snapshot interval time in cron spec. eg. every 5 hours '* */5 * * *'",
		Destination: &cmds.ServerConfig.EtcdSnapshotCron,
		Value:       "0 */12 * * *",
	},
	&cli.IntFlag{
		Name:        "etcd-snapshot-retention",
		Usage:       "(db) Number of snapshots to retain",
		Destination: &cmds.ServerConfig.EtcdSnapshotRetention,
		Value:       defaultSnapshotRentention,
	},
	&cli.StringFlag{
		Name:        "etcd-snapshot-dir",
		Usage:       "(db) Directory to save db snapshots. (Default location: ${data-dir}/db/snapshots)",
		Destination: &cmds.ServerConfig.EtcdSnapshotDir,
	},
	&cli.BoolFlag{
		Name:        "etcd-snapshot-compress",
		Usage:       "(db) Compress etcd snapshot",
		Destination: &cmds.ServerConfig.EtcdSnapshotCompress,
	},
	&cli.BoolFlag{
		Name:        "etcd-s3",
		Usage:       "(db) Enable backup to S3",
		Destination: &cmds.ServerConfig.EtcdS3,
	},
	&cli.StringFlag{
		Name:        "etcd-s3-endpoint",
		Usage:       "(db) S3 endpoint url",
		Destination: &cmds.ServerConfig.EtcdS3Endpoint,
		Value:       "s3.amazonaws.com",
	},
	&cli.StringFlag{
		Name:        "etcd-s3-endpoint-ca",
		Usage:       "(db) S3 custom CA cert to connect to S3 endpoint",
		Destination: &cmds.ServerConfig.EtcdS3EndpointCA,
	},
	&cli.BoolFlag{
		Name:        "etcd-s3-skip-ssl-verify",
		Usage:       "(db) Disables S3 SSL certificate validation",
		Destination: &cmds.ServerConfig.EtcdS3SkipSSLVerify,
	},
	&cli.StringFlag{
		Name:        "etcd-s3-access-key",
		Usage:       "(db) S3 access key",
		EnvVar:      "AWS_ACCESS_KEY_ID",
		Destination: &cmds.ServerConfig.EtcdS3AccessKey,
	},
	&cli.StringFlag{
		Name:        "etcd-s3-secret-key",
		Usage:       "(db) S3 secret key",
		EnvVar:      "AWS_SECRET_ACCESS_KEY",
		Destination: &cmds.ServerConfig.EtcdS3SecretKey,
	},
	&cli.StringFlag{
		Name:        "etcd-s3-bucket",
		Usage:       "(db) S3 bucket name",
		Destination: &cmds.ServerConfig.EtcdS3BucketName,
	},
	&cli.StringFlag{
		Name:        "etcd-s3-region",
		Usage:       "(db) S3 region / bucket location (optional)",
		Destination: &cmds.ServerConfig.EtcdS3Region,
		Value:       "us-east-1",
	},
	&cli.StringFlag{
		Name:        "etcd-s3-folder",
		Usage:       "(db) S3 folder",
		Destination: &cmds.ServerConfig.EtcdS3Folder,
	},
	&cli.BoolFlag{
		Name:        "etcd-s3-insecure",
		Usage:       "(db) Disables S3 over HTTPS",
		Destination: &cmds.ServerConfig.EtcdS3Insecure,
	},
	&cli.DurationFlag{
		Name:        "etcd-s3-timeout",
		Usage:       "(db) S3 timeout",
		Destination: &cmds.ServerConfig.EtcdS3Timeout,
		Value:       30 * time.Second,
	},
	cli.StringSliceFlag{
		Name:  "disable",
		Usage: "(components) Do not deploy packaged components and delete any deployed components (valid items: " + cmds.DisableItems + ")",
	},
	cli.BoolFlag{
		Name:        "disable-scheduler",
		Usage:       "(components) Disable Kubernetes default scheduler",
		Destination: &cmds.ServerConfig.DisableScheduler,
	},
	cli.BoolFlag{
		Name:        "disable-cloud-controller",
		Usage:       "(components) Disable " + version.Program + " default cloud controller manager",
		Destination: &cmds.ServerConfig.DisableCCM,
	},
	cli.BoolFlag{
		Name:        "disable-kube-proxy",
		Usage:       "(components) Disable running kube-proxy",
		Destination: &cmds.ServerConfig.DisableKubeProxy,
	},
	cli.BoolFlag{
		Name:        "disable-apiserver",
		Hidden:      true,
		Usage:       "(experimental/components) Disable running api server",
		Destination: &cmds.ServerConfig.DisableAPIServer,
	},
	cli.BoolFlag{
		Name:        "disable-controller-manager",
		Hidden:      true,
		Usage:       "(experimental/components) Disable running kube-controller-manager",
		Destination: &cmds.ServerConfig.DisableControllerManager,
	},
	cli.BoolFlag{
		Name:        "disable-etcd",
		Hidden:      true,
		Usage:       "(experimental/components) Disable running etcd",
		Destination: &cmds.ServerConfig.DisableETCD,
	},
	NodeNameFlag,
	NodeLabels,
	NodeTaints,
	ImageCredProvBinDirFlag,
	ImageCredProvConfigFlag,
	CRIEndpointFlag,
	SnapshotterFlag,
	PrivateRegistryFlag,
	AirgapExtraRegistryFlag,
	NodeIPFlag,
	NodeExternalIPFlag,
	ResolvConfFlag,
	ExtraKubeletArgs,
	ExtraKubeProxyArgs,
	ProtectKernelDefaultsFlag,
	cli.StringFlag{
		Name:        "agent-token",
		Usage:       "(cluster) Shared secret used to join agents to the cluster, but not servers",
		Destination: &cmds.ServerConfig.AgentToken,
		EnvVar:      version.ProgramUpper + "_AGENT_TOKEN",
	},
	cli.StringFlag{
		Name:        "agent-token-file",
		Usage:       "(cluster) File containing the agent secret",
		Destination: &cmds.ServerConfig.AgentTokenFile,
		EnvVar:      version.ProgramUpper + "_AGENT_TOKEN_FILE",
	},
	cli.StringFlag{
		Name:        "server,s",
		Usage:       "(cluster) Server to connect to, used to join a cluster",
		EnvVar:      version.ProgramUpper + "_URL",
		Destination: &cmds.ServerConfig.ServerURL,
	},
	cli.BoolFlag{
		Name:        "cluster-reset",
		Usage:       "(cluster) Forget all peers and become sole member of a new cluster",
		EnvVar:      version.ProgramUpper + "_CLUSTER_RESET",
		Destination: &cmds.ServerConfig.ClusterReset,
	},
	&cli.StringFlag{
		Name:        "cluster-reset-restore-path",
		Usage:       "(db) Path to snapshot file to be restored",
		Destination: &cmds.ServerConfig.ClusterResetRestorePath,
	},
	cli.BoolFlag{
		Name:        "secrets-encryption",
		Usage:       "(experimental) Enable Secret encryption at rest",
		Destination: &cmds.ServerConfig.EncryptSecrets,
	},
	cli.StringFlag{
		Name:        "system-default-registry",
		Usage:       "(image) Private registry to be used for all system images",
		EnvVar:      version.ProgramUpper + "_SYSTEM_DEFAULT_REGISTRY",
		Destination: &cmds.ServerConfig.SystemDefaultRegistry,
	},
	&SELinuxFlag,
	LBServerPortFlag,
}

func NewServerCommand(action func(*cli.Context) error) cli.Command {
	return cli.Command{
		Name:      "server",
		Usage:     "Run management server",
		UsageText: appName + " server [OPTIONS]",
		Action:    action,
		Flags:     ServerFlags,
	}
}

func ServerRun(clx *cli.Context) error {
	validateCloudProviderName(ServerRole)
	validateProfile(clx, ServerRole)
	validateCNI(clx)
	return rke2.Server(clx)
}

func validateCNI(clx *cli.Context) {
	cnis := []string{}
	for _, cni := range clx.StringSlice("cni") {
		for _, v := range strings.Split(cni, ",") {
			cnis = append(cnis, v)
		}
	}

	switch len(cnis) {
	case 0:
		cnis = append(cnis, "canal")
		fallthrough
	case 1:
		if cnis[0] == "multus" {
			logrus.Fatal("invalid value provided for --cni flag: multus must be used alongside another primary cni selection")
		}
		clx.Set("disable", "rke2-multus")
	case 2:
		if cnis[0] == "multus" {
			cnis = cnis[1:]
		} else {
			logrus.Fatal("invalid values provided for --cni flag: may only provide multiple values if multus is the first value")
		}
	default:
		logrus.Fatal("invalid values provided for --cni flag: may not provide more than two values")
	}

	switch {
	case cnis[0] == "none":
		fallthrough
	case slice.ContainsString(CNIItems, cnis[0]):
		for _, d := range CNIItems {
			if cnis[0] != d {
				clx.Set("disable", "rke2-"+d)
				clx.Set("disable", "rke2-"+d+"-crd")
			}
		}
	default:
		logrus.Fatal("invalid value provided for --cni flag")
	}
}
