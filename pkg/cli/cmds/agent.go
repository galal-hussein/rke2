package cmds

import (
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/configfilearg"
	"github.com/k3s-io/k3s/pkg/version"
	"github.com/rancher/rke2/pkg/config"
	"github.com/urfave/cli"
)

var (
	AgentConfig     = config.Agent{}
	deprecatedFlags = []cli.Flag{
		&cli.StringFlag{
			Name:   "system-default-registry",
			Usage:  "(deprecated) This flag is no longer supported on agents",
			EnvVar: "RKE2_SYSTEM_DEFAULT_REGISTRY",
			Hidden: true,
		},
	}
	AgentTokenFlag = cli.StringFlag{
		Name:        "token,t",
		Usage:       "(cluster) Token to use for authentication",
		EnvVar:      version.ProgramUpper + "_TOKEN",
		Destination: &cmds.AgentConfig.Token,
	}
	NodeIPFlag = cli.StringSliceFlag{
		Name:  "node-ip,i",
		Usage: "(agent/networking) IPv4/IPv6 addresses to advertise for node",
		Value: &cmds.AgentConfig.NodeIP,
	}
	NodeExternalIPFlag = cli.StringSliceFlag{
		Name:  "node-external-ip",
		Usage: "(agent/networking) IPv4/IPv6 external IP addresses to advertise for node",
		Value: &cmds.AgentConfig.NodeExternalIP,
	}
	NodeNameFlag = cli.StringFlag{
		Name:        "node-name",
		Usage:       "(agent/node) Node name",
		EnvVar:      version.ProgramUpper + "_NODE_NAME",
		Destination: &cmds.AgentConfig.NodeName,
	}
	CRIEndpointFlag = cli.StringFlag{
		Name:        "container-runtime-endpoint",
		Usage:       "(agent/runtime) Disable embedded containerd and use alternative CRI implementation",
		Destination: &cmds.AgentConfig.ContainerRuntimeEndpoint,
	}
	PrivateRegistryFlag = cli.StringFlag{
		Name:        "private-registry",
		Usage:       "(agent/runtime) Private registry configuration file",
		Destination: &cmds.AgentConfig.PrivateRegistry,
		Value:       "/etc/rancher/" + version.Program + "/registries.yaml",
	}
	AirgapExtraRegistryFlag = cli.StringSliceFlag{
		Name:   "airgap-extra-registry",
		Usage:  "(agent/runtime) Additional registry to tag airgap images as being sourced from",
		Value:  &cmds.AgentConfig.AirgapExtraRegistry,
		Hidden: true,
	}
	SnapshotterFlag = cli.StringFlag{
		Name:        "snapshotter",
		Usage:       "(agent/runtime) Override default containerd snapshotter",
		Destination: &cmds.AgentConfig.Snapshotter,
		Value:       cmds.DefaultSnapshotter,
	}
	ResolvConfFlag = cli.StringFlag{
		Name:        "resolv-conf",
		Usage:       "(agent/networking) Kubelet resolv.conf file",
		EnvVar:      version.ProgramUpper + "_RESOLV_CONF",
		Destination: &cmds.AgentConfig.ResolvConf,
	}
	ExtraKubeletArgs = cli.StringSliceFlag{
		Name:  "kubelet-arg",
		Usage: "(agent/flags) Customized flag for kubelet process",
		Value: &cmds.AgentConfig.ExtraKubeletArgs,
	}
	ExtraKubeProxyArgs = cli.StringSliceFlag{
		Name:  "kube-proxy-arg",
		Usage: "(agent/flags) Customized flag for kube-proxy process",
		Value: &cmds.AgentConfig.ExtraKubeProxyArgs,
	}
	NodeTaints = cli.StringSliceFlag{
		Name:  "node-taint",
		Usage: "(agent/node) Registering kubelet with set of taints",
		Value: &cmds.AgentConfig.Taints,
	}
	NodeLabels = cli.StringSliceFlag{
		Name:  "node-label",
		Usage: "(agent/node) Registering and starting kubelet with set of labels",
		Value: &cmds.AgentConfig.Labels,
	}
	ImageCredProvBinDirFlag = cli.StringFlag{
		Name:        "image-credential-provider-bin-dir",
		Usage:       "(agent/node) The path to the directory where credential provider plugin binaries are located",
		Destination: &cmds.AgentConfig.ImageCredProvBinDir,
		Value:       "/var/lib/rancher/credentialprovider/bin",
	}
	ImageCredProvConfigFlag = cli.StringFlag{
		Name:        "image-credential-provider-config",
		Usage:       "(agent/node) The path to the credential provider plugin config file",
		Destination: &cmds.AgentConfig.ImageCredProvConfig,
		Value:       "/var/lib/rancher/credentialprovider/config.yaml",
	}
	ProtectKernelDefaultsFlag = cli.BoolFlag{
		Name:        "protect-kernel-defaults",
		Usage:       "(agent/node) Kernel tuning behavior. If set, error if kernel tunables are different than kubelet defaults.",
		Destination: &cmds.AgentConfig.ProtectKernelDefaults,
	}
	SELinuxFlag = cli.BoolFlag{
		Name:        "selinux",
		Usage:       "(agent/node) Enable SELinux in containerd",
		Hidden:      false,
		Destination: &cmds.AgentConfig.EnableSELinux,
		EnvVar:      version.ProgramUpper + "_SELINUX",
	}
	LBServerPortFlag = cli.IntFlag{
		Name:        "lb-server-port",
		Usage:       "(agent/node) Local port for supervisor client load-balancer. If the supervisor and apiserver are not colocated an additional port 1 less than this port will also be used for the apiserver client load-balancer.",
		Hidden:      false,
		Destination: &cmds.AgentConfig.LBServerPort,
		EnvVar:      version.ProgramUpper + "_LB_SERVER_PORT",
		Value:       6444,
	}
	AgentFlags = []cli.Flag{
		ConfigFlag,
		DebugFlag,
		VLevel,
		VModule,
		LogFile,
		AlsoLogToStderr,
		AgentTokenFlag,
		cli.StringFlag{
			Name:        "token-file",
			Usage:       "(cluster) Token file to use for authentication",
			EnvVar:      version.ProgramUpper + "_TOKEN_FILE",
			Destination: &cmds.AgentConfig.TokenFile,
		},
		cli.StringFlag{
			Name:        "server,s",
			Usage:       "(cluster) Server to connect to",
			EnvVar:      version.ProgramUpper + "_URL",
			Destination: &cmds.AgentConfig.ServerURL,
		},
		cli.StringFlag{
			Name:        "data-dir,d",
			Usage:       "(agent/data) Folder to hold state",
			Destination: &cmds.AgentConfig.DataDir,
			Value:       "/var/lib/rancher/" + version.Program + "",
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
		&SELinuxFlag,
		LBServerPortFlag,
	}
)

func NewAgentCommand(action func(ctx *cli.Context) error) cli.Command {
	cmd := cli.Command{
		Name:      "agent",
		Usage:     "Run node agent",
		UsageText: appName + " agent [OPTIONS]",
		Before:    cmds.CheckSELinuxFlags,
		Action:    action,
		Flags:     AgentFlags,
	}
	cmd.Flags = append(cmd.Flags, commonFlag...)
	cmd.Flags = append(cmd.Flags, deprecatedFlags...)
	cmd.Subcommands = agentSubcommands()
	configfilearg.DefaultParser.ValidFlags[cmd.Name] = cmd.Flags
	return cmd
}

func agentSubcommands() cli.Commands {
	subcommands := []cli.Command{
		// subcommands used by both windows/linux, none yet
	}

	// linux/windows only subcommands
	subcommands = append(subcommands, serviceSubcommand)

	return subcommands
}

// func AgentRun(clx *cli.Context) error {
// 	validateCloudProviderName(clx, Agent)
// 	validateProfile(clx, Agent)
// 	if err := windows.StartService(); err != nil {
// 		return err
// 	}
// 	return rke2.Agent(clx, config)
// }
