package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/rancher/rke2/pkg/configfilearg"
	"github.com/urfave/cli"
	utilnet "k8s.io/apimachinery/pkg/util/net"
)

const (
	DefaultPodManifestPath = "pod-manifests"
)

type Node struct {
	Docker                   bool
	ContainerRuntimeEndpoint string
	NoFlannel                bool
	SELinux                  bool
	FlannelBackend           string
	FlannelConfFile          string
	FlannelConfOverride      bool
	FlannelIface             *net.Interface
	FlannelIPv6Masq          bool
	Containerd               Containerd
	Images                   string
	AgentConfig              Agent
	Token                    string
	Certificate              *tls.Certificate
	ServerHTTPSPort          int
}

type Containerd struct {
	Address  string
	Log      string
	Root     string
	State    string
	Config   string
	Opt      string
	Template string
	SELinux  bool
}

type Agent struct {
	AgentReady               chan<- struct{}
	AirgapExtraRegistry      cli.StringSlice
	APIAddressCh             chan []string
	ClientCA                 string
	ClusterCIDR              *net.IPNet
	ClusterCIDRs             []*net.IPNet
	ClusterDNS               net.IP
	ClusterDNSs              []net.IP
	ClusterDomain            string
	ClusterReset             bool
	ClusterSecret            string
	CNIBinDir                string
	CNIConfDir               string
	CNIPlugin                bool
	ContainerRuntimeEndpoint string
	DataDir                  string
	Debug                    bool
	DisableCCM               bool
	DisableLoadBalancer      bool
	DisableNPC               bool
	DisableServiceLB         bool
	Docker                   bool
	EnableIPv6               bool
	EnableSELinux            bool
	ETCDAgent                bool
	ExtraKubeletArgs         cli.StringSlice
	ExtraKubeProxyArgs       cli.StringSlice
	FlannelConf              string
	FlannelIface             string
	ImageCredProvBinDir      string
	ImageCredProvConfig      string
	ImageServiceSocket       string
	IPSECPSK                 string
	KubeConfigK3sController  string
	KubeConfigKubelet        string
	KubeConfigKubeProxy      string
	Labels                   cli.StringSlice
	LBServerPort             int
	ListenAddress            string
	NodeConfigPath           string
	NodeExternalIP           cli.StringSlice
	NodeExternalIPs          []net.IP
	NodeExternalIPStr        string
	NodeIP                   cli.StringSlice
	NodeIPStr                string
	NodeIPs                  []net.IP
	NodeLabels               []string
	NodeName                 string
	NodeTaints               []string
	NoFlannel                bool
	PauseImage               string
	PodManifests             string
	PrivateRegistry          string
	ProtectKernelDefaults    bool
	ResolvConf               string
	RootDir                  string
	Rootless                 bool
	RuntimeSocket            string
	ServerURL                string
	ServiceCIDR              *net.IPNet
	ServiceCIDRs             []*net.IPNet
	ServiceNodePortRange     *utilnet.PortRange
	ServingKubeletCert       string
	ServingKubeletKey        string
	Snapshotter              string
	StrongSwanDir            string
	SystemDefaultRegistry    string
	Taints                   cli.StringSlice
	TokenFile                string
	Token                    string
	WithNodeID               bool
	DefaultParser            *configfilearg.Parser
}

const (
	FlannelBackendNone      = "none"
	FlannelBackendVXLAN     = "vxlan"
	FlannelBackendHostGW    = "host-gw"
	FlannelBackendIPSEC     = "ipsec"
	FlannelBackendWireguard = "wireguard"
	CertificateRenewDays    = 90
)

type ArgString []string

func (a ArgString) String() string {
	b := strings.Builder{}
	for _, s := range a {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString(s)
	}
	return b.String()
}

// GetArgs appends extra arguments to existing arguments overriding any default options.
func GetArgs(argsMap map[string]string, extraArgs []string) []string {
	const hyphens = "--"

	// add extra args to args map to override any default option
	for _, arg := range extraArgs {
		splitArg := strings.SplitN(strings.TrimPrefix(arg, hyphens), "=", 2)
		if len(splitArg) < 2 {
			argsMap[splitArg[0]] = "true"
			continue
		}
		argsMap[splitArg[0]] = splitArg[1]
	}
	var args []string
	for arg, value := range argsMap {
		cmd := fmt.Sprintf("%s%s=%s", hyphens, strings.TrimPrefix(arg, hyphens), value)
		args = append(args, cmd)
	}
	sort.Strings(args)
	return args
}
