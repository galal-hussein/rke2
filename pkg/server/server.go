package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	systemd "github.com/coreos/go-systemd/daemon"
	"github.com/erikdubbelboer/gspt"
	"github.com/pkg/errors"
	"github.com/rancher/k3s/pkg/agent"
	"github.com/rancher/k3s/pkg/agent/loadbalancer"
	"github.com/rancher/k3s/pkg/cli/cmds"
	"github.com/rancher/k3s/pkg/clientaccess"
	"github.com/rancher/k3s/pkg/datadir"
	"github.com/rancher/k3s/pkg/etcd"
	"github.com/rancher/k3s/pkg/server"
	"github.com/rancher/k3s/pkg/token"
	"github.com/rancher/k3s/pkg/util"
	"github.com/rancher/k3s/pkg/version"
	"github.com/rancher/rke2/pkg/config"
	"github.com/rancher/wrangler/pkg/signals"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	kubeapiserverflag "k8s.io/component-base/cli/flag"
	"k8s.io/kubernetes/pkg/controlplane"
	utilsnet "k8s.io/utils/net"
)

type Server struct {
	ServerConfig      *config.Server
	AgentConfig       *config.Agent
	Controllers       server.CustomControllers
	LeaderControllers server.CustomControllers
}

func (s *Server) Run(app *cli.Context) error {
	var (
		err error
	)

	// hide process arguments from ps output, since they may contain
	// database credentials or other secrets.
	gspt.SetProcTitle(os.Args[0] + " server")

	// Initialize logging, and subprocess reaping if necessary.
	// Log output redirection and subprocess reaping both require forking.
	if err := cmds.InitLogging(); err != nil {
		return err
	}

	agentReady := make(chan struct{})

	s.ServerConfig.Runtime = &config.ControlRuntime{AgentReady: agentReady}

	if s.ServerConfig.AgentTokenFile != "" {
		s.ServerConfig.AgentToken, err = token.ReadFile(s.ServerConfig.AgentTokenFile)
		if err != nil {
			return err
		}
	}
	if s.ServerConfig.TokenFile != "" {
		s.ServerConfig.Token, err = token.ReadFile(s.ServerConfig.TokenFile)
		if err != nil {
			return err
		}
	}

	if s.ServerConfig.EtcdDisableSnapshots {
		logrus.Info("ETCD snapshots are disabled")
	}

	if s.ServerConfig.ClusterResetRestorePath != "" && !s.ServerConfig.ClusterReset {
		return errors.New("invalid flag use; --cluster-reset required with --cluster-reset-restore-path")
	}

	if s.ServerConfig.DisableETCD && s.ServerConfig.ServerURL == "" {
		return errors.New("invalid flag use; --server is required with --disable-etcd")
	}

	if s.ServerConfig.DisableAPIServer {
		s.ServerConfig.APIServerPort = cmds.AgentConfig.LBServerPort - 1
	}

	if len(cmds.AgentConfig.NodeIP) != 0 {
		// ignoring the error here is fine since etcd will fall back to the interface's IPv4 address
		s.ServerConfig.PrivateIP, _ = util.GetFirst4String(s.AgentConfig.NodeIP)
	}

	// if not set, try setting advertise-ip from agent node-external-ip
	if s.ServerConfig.AdvertiseIP == "" && len(s.AgentConfig.NodeExternalIP) != 0 {
		s.ServerConfig.AdvertiseIP, _ = util.GetFirst4String(s.AgentConfig.NodeExternalIP)
	}

	// if not set, try setting advertise-ip from agent node-ip
	if s.ServerConfig.AdvertiseIP == "" && len(s.AgentConfig.NodeIP) != 0 {
		s.ServerConfig.AdvertiseIP, _ = util.GetFirst4String(s.AgentConfig.NodeIP)
	}

	// if we ended up with any advertise-ips, ensure they're added to the SAN list;
	// note that kube-apiserver does not support dual-stack advertise-ip as of 1.21.0:
	/// https://github.com/kubernetes/kubeadm/issues/1612#issuecomment-772583989
	if s.ServerConfig.AdvertiseIP != "" {
		s.ServerConfig.TLSSan = append(s.ServerConfig.TLSSan, s.ServerConfig.AdvertiseIP)
	}

	// Ensure that we add the localhost name/ip and node name/ip to the SAN list. This list is shared by the
	// certs for the supervisor, kube-apiserver cert, and etcd. DNS entries for the in-cluster kubernetes
	// service endpoint are added later when the certificates are created.
	nodeName, nodeIPs, err := util.GetHostnameAndIPs(s.AgentConfig.NodeName, s.AgentConfig.NodeIP)
	if err != nil {
		return err
	}
	s.ServerConfig.ServerNodeName = nodeName
	s.ServerConfig.TLSSan = append(s.ServerConfig.TLSSan, "127.0.0.1", "localhost", nodeName)
	for _, ip := range nodeIPs {
		s.ServerConfig.TLSSan = append(s.ServerConfig.TLSSan, ip.String())
	}

	// configure ClusterIPRanges
	if len(s.ServerConfig.ClusterCIDR) == 0 {
		s.ServerConfig.ClusterCIDR = []string{"10.42.0.0/16"}
	}
	for _, cidr := range cmds.ServerConfig.ClusterCIDR {
		for _, v := range strings.Split(cidr, ",") {
			_, parsed, err := net.ParseCIDR(v)
			if err != nil {
				return errors.Wrapf(err, "invalid cluster-cidr %s", v)
			}
			s.ServerConfig.ClusterIPRanges = append(s.ServerConfig.ClusterIPRanges, parsed)
		}
	}

	// set ClusterIPRange to the first IPv4 block, for legacy clients
	clusterIPRange, err := util.GetFirst4Net(s.ServerConfig.ClusterIPRanges)
	if err != nil {
		return errors.Wrap(err, "cannot configure IPv4 cluster-cidr")
	}
	s.ServerConfig.ClusterIPRange = clusterIPRange

	// configure ServiceIPRanges
	if len(cmds.ServerConfig.ServiceCIDR) == 0 {
		cmds.ServerConfig.ServiceCIDR.Set("10.43.0.0/16")
	}
	for _, cidr := range cmds.ServerConfig.ServiceCIDR {
		for _, v := range strings.Split(cidr, ",") {
			_, parsed, err := net.ParseCIDR(v)
			if err != nil {
				return errors.Wrapf(err, "invalid service-cidr %s", v)
			}
			s.ServerConfig.ServiceIPRanges = append(s.ServerConfig.ServiceIPRanges, parsed)
		}
	}

	// set ServiceIPRange to the first IPv4 block, for legacy clients
	serviceIPRange, err := util.GetFirst4Net(s.ServerConfig.ServiceIPRanges)
	if err != nil {
		return errors.Wrap(err, "cannot configure IPv4 service-cidr")
	}
	s.ServerConfig.ServiceIPRange = serviceIPRange

	s.ServerConfig.ServiceNodePortRange, err = utilnet.ParsePortRange(s.ServerConfig.ServiceNodePortRangeStr)
	if err != nil {
		return errors.Wrapf(err, "invalid port range %s", s.ServerConfig.ServiceNodePortRangeStr)
	}

	// the apiserver service does not yet support dual-stack operation
	_, apiServerServiceIP, err := controlplane.ServiceIPRange(*s.ServerConfig.ServiceIPRange)
	if err != nil {
		return err
	}
	s.ServerConfig.TLSSan = append(s.ServerConfig.TLSSan, apiServerServiceIP.String())

	// If cluster-dns CLI arg is not set, we set ClusterDNS address to be the first IPv4 ServiceCIDR network + 10,
	// i.e. when you set service-cidr to 192.168.0.0/16 and don't provide cluster-dns, it will be set to 192.168.0.10
	// If there are no IPv4 ServiceCIDRs, an error will be raised.
	if len(s.ServerConfig.ClusterDNS) == 0 {
		clusterDNS, err := utilsnet.GetIndexedIP(s.ServerConfig.ServiceIPRange, 10)
		if err != nil {
			return errors.Wrap(err, "cannot configure default cluster-dns address")
		}
		s.ServerConfig.ClusterDNSIP = clusterDNS
		s.ServerConfig.ClusterDNSIPs = []net.IP{s.ServerConfig.ClusterDNSIP}
	} else {
		for _, ip := range s.ServerConfig.ClusterDNS {
			for _, v := range strings.Split(ip, ",") {
				parsed := net.ParseIP(v)
				if parsed == nil {
					return fmt.Errorf("invalid cluster-dns address %s", v)
				}
				s.ServerConfig.ClusterDNSIPs = append(s.ServerConfig.ClusterDNSIPs, parsed)
			}
		}
		// Set ClusterDNS to the first IPv4 address, for legacy clients
		clusterDNS4IP, err := util.GetFirst4(s.ServerConfig.ClusterDNSIPs)
		if err != nil {
			return errors.Wrap(err, "cannot configure IPv4 cluster-dns address")
		}
		s.ServerConfig.ClusterDNSIP = clusterDNS4IP
	}

	if err := s.validateNetworkConfiguration(); err != nil {
		return err
	}

	s.ServerConfig.Skips = map[string]bool{}
	for _, noDeploy := range app.StringSlice("no-deploy") {
		for _, v := range strings.Split(noDeploy, ",") {
			v = strings.TrimSpace(v)
			s.ServerConfig.Skips[v] = true
		}
	}
	s.ServerConfig.Disables = map[string]bool{}
	for _, disable := range app.StringSlice("disable") {
		for _, v := range strings.Split(disable, ",") {
			v = strings.TrimSpace(v)
			s.ServerConfig.Skips[v] = true
			s.ServerConfig.Disables[v] = true
		}
	}
	if s.ServerConfig.Skips["servicelb"] {
		s.ServerConfig.DisableServiceLB = true
	}

	if s.ServerConfig.DisableCCM {
		s.ServerConfig.Skips["ccm"] = true
		s.ServerConfig.Disables["ccm"] = true
	}

	tlsMinVersionArg := getArgValueFromList("tls-min-version", s.ServerConfig.ExtraAPIArgs)
	s.ServerConfig.TLSMinVersion, err = kubeapiserverflag.TLSVersion(tlsMinVersionArg)
	if err != nil {
		return errors.Wrap(err, "invalid tls-min-version")
	}

	s.ServerConfig.StartupHooks = append(s.ServerConfig.StartupHooks, s.ServerConfig.StartupHooks...)

	s.ServerConfig.LeaderControllers = append(s.ServerConfig.LeaderControllers, s.LeaderControllers...)
	s.ServerConfig.Controllers = append(s.ServerConfig.Controllers, s.Controllers...)

	// TLS config based on mozilla ssl-config generator
	// https://ssl-config.mozilla.org/#server=golang&version=1.13.6&config=intermediate&guideline=5.4
	// Need to disable the TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 Cipher for TLS1.2
	tlsCipherSuitesArg := getArgValueFromList("tls-cipher-suites", s.ServerConfig.ExtraAPIArgs)
	tlsCipherSuites := strings.Split(tlsCipherSuitesArg, ",")
	for i := range tlsCipherSuites {
		tlsCipherSuites[i] = strings.TrimSpace(tlsCipherSuites[i])
	}
	if len(tlsCipherSuites) == 0 || tlsCipherSuites[0] == "" {
		tlsCipherSuites = []string{
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		}
	}
	s.ServerConfig.TLSCipherSuites, err = kubeapiserverflag.TLSCipherSuites(tlsCipherSuites)
	if err != nil {
		return errors.Wrap(err, "invalid tls-cipher-suites")
	}

	// make sure components are disabled so we only perform a restore
	// and bail out
	if s.ServerConfig.ClusterResetRestorePath != "" && s.ServerConfig.ClusterReset {
		s.ServerConfig.ClusterInit = true
		s.ServerConfig.DisableAPIServer = true
		s.ServerConfig.DisableControllerManager = true
		s.ServerConfig.DisableScheduler = true
		s.ServerConfig.DisableCCM = true

		// only close the agentReady channel in case of k3s restoration, because k3s does not start
		// the agent until server returns successfully, unlike rke2's agent which starts in parallel
		// with the server
		if s.ServerConfig.SupervisorPort == s.ServerConfig.HTTPSPort {
			close(agentReady)
		}

		dataDir, err := datadir.LocalHome(s.ServerConfig.DataDir, false)
		if err != nil {
			return err
		}
		// delete local loadbalancers state for apiserver and supervisor servers
		loadbalancer.ResetLoadBalancer(filepath.Join(dataDir, "agent"), loadbalancer.SupervisorServiceName)
		loadbalancer.ResetLoadBalancer(filepath.Join(dataDir, "agent"), loadbalancer.APIServerServiceName)

		// at this point we're doing a restore. Check to see if we've
		// passed in a token and if not, check if the token file exists.
		// If it doesn't, return an error indicating the token is necessary.
		if s.ServerConfig.Token == "" {
			tokenFile := filepath.Join(dataDir, "server", "token")
			if _, err := os.Stat(tokenFile); err != nil {
				if os.IsNotExist(err) {
					return errors.New(tokenFile + " does not exist, please pass --token to complete the restoration")
				}
			}
		}
	}

	logrus.Info("Starting " + version.Program + " " + app.App.Version)

	notifySocket := os.Getenv("NOTIFY_SOCKET")

	ctx := signals.SetupSignalContext()

	if err := server.StartServer(ctx, &s.ServerConfig, cfg); err != nil {
		return err
	}

	go func() {
		if !s.ServerConfig.DisableAPIServer {
			<-s.ServerConfig.Runtime.APIServerReady
			logrus.Info("Kube API server is now running")
		} else {
			<-s.ServerConfig.Runtime.ETCDReady
			logrus.Info("ETCD server is now running")
		}

		logrus.Info(version.Program + " is up and running")
		if (s.ServerConfig.DisableAgent || s.ServerConfig.DisableAPIServer) && notifySocket != "" {
			os.Setenv("NOTIFY_SOCKET", notifySocket)
			systemd.SdNotify(true, "READY=1\n")
		}
	}()

	if s.ServerConfig.DisableAgent {
		close(agentReady)
		<-ctx.Done()
		return nil
	}

	ip := s.ServerConfig.BindAddress
	if ip == "" {
		ip = "127.0.0.1"
	}

	url := fmt.Sprintf("https://%s:%d", ip, s.ServerConfig.SupervisorPort)
	token, err := clientaccess.FormatToken(s.ServerConfig.Runtime.AgentToken, s.ServerConfig.Runtime.ServerCA)
	if err != nil {
		return err
	}

	agentConfig := cmds.AgentConfig
	agentConfig.AgentReady = agentReady
	agentConfig.Debug = app.GlobalBool("debug")
	agentConfig.DataDir = filepath.Dir(s.ServerConfig.DataDir)
	agentConfig.ServerURL = url
	agentConfig.Token = token
	agentConfig.DisableLoadBalancer = !s.ServerConfig.DisableAPIServer
	agentConfig.DisableServiceLB = s.ServerConfig.DisableServiceLB
	agentConfig.ETCDAgent = s.ServerConfig.DisableAPIServer
	agentConfig.ClusterReset = s.ServerConfig.ClusterReset

	agentConfig.Rootless = s.ServerConfig.Rootless

	if agentConfig.Rootless {
		// let agent specify Rootless kubelet flags, but not unshare twice
		agentConfig.RootlessAlreadyUnshared = true
	}

	if s.ServerConfig.DisableAPIServer {
		// initialize the apiAddress Channel for receiving the api address from etcd
		agentConfig.APIAddressCh = make(chan string, 1)
		s.setAPIAddressChannel(ctx)
		defer close(agentConfig.APIAddressCh)
	}
	return agent.Run(ctx, agentConfig)
}

// validateNetworkConfig ensures that the network configuration values make sense.
func (s *Server) validateNetworkConfiguration() error {
	// Dual-stack operation requires fairly extensive manual configuration at the moment - do some
	// preflight checks to make sure that the user isn't trying to use flannel/npc, or trying to
	// enable dual-stack DNS (which we don't currently support since it's not easy to template)
	dualCluster, err := utilsnet.IsDualStackCIDRs(s.ServerConfig.ClusterIPRanges)
	if err != nil {
		return errors.Wrap(err, "failed to validate cluster-cidr")
	}
	dualService, err := utilsnet.IsDualStackCIDRs(s.ServerConfig.ServiceIPRanges)
	if err != nil {
		return errors.Wrap(err, "failed to validate service-cidr")
	}
	dualDNS, err := utilsnet.IsDualStackIPs(s.ServerConfig.ClusterDNSIPs)
	if err != nil {
		return errors.Wrap(err, "failed to validate cluster-dns")
	}

	if (s.ServerConfig.DisableNPC == false) && (dualCluster || dualService) {
		return errors.New("network policy enforcement is not compatible with dual-stack operation; server must be restarted with --disable-network-policy")
	}
	if dualDNS == true {
		return errors.New("dual-stack cluster-dns is not supported")
	}

	return nil
}

// setAPIAddressChannel will try to get the api address key from etcd and when it succeed it will
// set the APIAddressCh channel with its value,the code will not block operation and will
// run the operation in a goroutine
func (s *Server) setAPIAddressChannel(ctx context.Context) {
	// start a goroutine to check for the server ip if set from etcd in case of rke2
	go s.getAPIAddressFromEtcd(ctx)
	return
}

func (s *Server) getAPIAddressFromEtcd(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		serverAddress, err := etcd.GetAPIServerURLFromETCD(ctx, s.ServerConfig)
		if err == nil {
			s.AgentConfig.ServerURL = "https://" + serverAddress
			s.AgentConfig.APIAddressCh <- s.AgentConfig.ServerURL
			break
		}
		logrus.Warn(err)
	}
}

func getArgValueFromList(searchArg string, argList []string) string {
	var value string
	for _, arg := range argList {
		splitArg := strings.SplitN(arg, "=", 2)
		if splitArg[0] == searchArg {
			value = splitArg[1]
			// break if we found our value
			break
		}
	}
	return value
}
