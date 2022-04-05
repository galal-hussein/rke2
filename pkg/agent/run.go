package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	systemd "github.com/coreos/go-systemd/daemon"
	"github.com/pkg/errors"
	"github.com/rancher/rke2/pkg/agent/config"
	"github.com/rancher/rke2/pkg/agent/containerd"
	"github.com/rancher/rke2/pkg/agent/netpol"
	"github.com/rancher/rke2/pkg/agent/proxy"
	"github.com/rancher/rke2/pkg/agent/syssetup"
	"github.com/rancher/rke2/pkg/agent/tunnel"
	"github.com/rancher/rke2/pkg/cgroups"
	"github.com/rancher/rke2/pkg/clientaccess"
	cp "github.com/rancher/rke2/pkg/cloudprovider"
	daemonconfig "github.com/rancher/rke2/pkg/config"
	"github.com/rancher/rke2/pkg/daemons/agent"
	"github.com/rancher/rke2/pkg/daemons/executor"
	"github.com/rancher/rke2/pkg/nodeconfig"
	"github.com/rancher/rke2/pkg/util"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	app2 "k8s.io/kubernetes/cmd/kube-proxy/app"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	utilsnet "k8s.io/utils/net"
	utilpointer "k8s.io/utils/pointer"
)

func (a *Agent) run(ctx context.Context, proxy proxy.Proxy) error {
	nodeConfig := config.Get(ctx, a.AgentConfig, proxy)

	dualCluster, err := utilsnet.IsDualStackCIDRs(nodeConfig.AgentConfig.ClusterCIDRs)
	if err != nil {
		return errors.Wrap(err, "failed to validate cluster-cidr")
	}
	dualService, err := utilsnet.IsDualStackCIDRs(nodeConfig.AgentConfig.ServiceCIDRs)
	if err != nil {
		return errors.Wrap(err, "failed to validate service-cidr")
	}
	dualNode, err := utilsnet.IsDualStackIPs(nodeConfig.AgentConfig.NodeIPs)
	if err != nil {
		return errors.Wrap(err, "failed to validate node-ip")
	}
	serviceIPv6 := utilsnet.IsIPv6CIDR(nodeConfig.AgentConfig.ServiceCIDR)
	clusterIPv6 := utilsnet.IsIPv6CIDR(nodeConfig.AgentConfig.ClusterCIDR)

	enableIPv6 := dualCluster || dualService || dualNode || serviceIPv6 || clusterIPv6
	conntrackConfig, err := getConntrackConfig(nodeConfig)
	if err != nil {
		return errors.Wrap(err, "failed to validate kube-proxy conntrack configuration")
	}
	syssetup.Configure(enableIPv6, conntrackConfig)
	nodeConfig.AgentConfig.EnableIPv6 = enableIPv6

	if err := setupCriCtlConfig(nodeConfig, a.AgentConfig.DataDir); err != nil {
		return err
	}

	if err := executor.Bootstrap(ctx, nodeConfig, a.AgentConfig.DataDir); err != nil {
		return err
	}

	if nodeConfig.ContainerRuntimeEndpoint == "" {
		if err := containerd.Run(ctx, nodeConfig); err != nil {
			return err
		}
	}
	nodeConfig.AgentConfig.DefaultParser = a.AgentConfig.DefaultParser

	// the agent runtime is ready to host workloads when containerd is up and the airgap
	// images have finished loading, as that portion of startup may block for an arbitrary
	// amount of time depending on how long it takes to import whatever the user has placed
	// in the images directory.
	if a.AgentConfig.AgentReady != nil {
		close(a.AgentConfig.AgentReady)
	}

	notifySocket := os.Getenv("NOTIFY_SOCKET")
	os.Unsetenv("NOTIFY_SOCKET")

	if err := setupTunnelAndRunAgent(ctx, nodeConfig, proxy); err != nil {
		return err
	}

	coreClient, err := coreClient(nodeConfig.AgentConfig.KubeConfigKubelet)
	if err != nil {
		return err
	}

	if err := util.WaitForAPIServerReady(ctx, coreClient, util.DefaultAPIServerReadyTimeout); err != nil {
		return errors.Wrap(err, "failed to wait for apiserver ready")
	}

	if err := configureNode(ctx, &nodeConfig.AgentConfig, coreClient.CoreV1().Nodes()); err != nil {
		return err
	}

	if !nodeConfig.AgentConfig.DisableNPC {
		if err := netpol.Run(ctx, nodeConfig); err != nil {
			return err
		}
	}

	os.Setenv("NOTIFY_SOCKET", notifySocket)
	systemd.SdNotify(true, "READY=1\n")

	<-ctx.Done()
	return ctx.Err()
}

// getConntrackConfig uses the kube-proxy code to parse the user-provided kube-proxy-arg values, and
// extract the conntrack settings so that K3s can set them itself. This allows us to soft-fail when
// running K3s in Docker, where kube-proxy is no longer allowed to set conntrack sysctls on newer kernels.
// When running rootless, we do not attempt to set conntrack sysctls - this behavior is copied from kubeadm.
func getConntrackConfig(nodeConfig *daemonconfig.Node) (*kubeproxyconfig.KubeProxyConntrackConfiguration, error) {
	ctConfig := &kubeproxyconfig.KubeProxyConntrackConfiguration{
		MaxPerCore:            utilpointer.Int32Ptr(0),
		Min:                   utilpointer.Int32Ptr(0),
		TCPEstablishedTimeout: &metav1.Duration{},
		TCPCloseWaitTimeout:   &metav1.Duration{},
	}

	if nodeConfig.AgentConfig.Rootless {
		return ctConfig, nil
	}

	cmd := app2.NewProxyCommand()
	if err := cmd.ParseFlags(daemonconfig.GetArgs(map[string]string{}, nodeConfig.AgentConfig.ExtraKubeProxyArgs)); err != nil {
		return nil, err
	}
	maxPerCore, err := cmd.Flags().GetInt32("conntrack-max-per-core")
	if err != nil {
		return nil, err
	}
	ctConfig.MaxPerCore = &maxPerCore
	min, err := cmd.Flags().GetInt32("conntrack-min")
	if err != nil {
		return nil, err
	}
	ctConfig.Min = &min
	establishedTimeout, err := cmd.Flags().GetDuration("conntrack-tcp-timeout-established")
	if err != nil {
		return nil, err
	}
	ctConfig.TCPEstablishedTimeout.Duration = establishedTimeout
	closeWaitTimeout, err := cmd.Flags().GetDuration("conntrack-tcp-timeout-close-wait")
	if err != nil {
		return nil, err
	}
	ctConfig.TCPCloseWaitTimeout.Duration = closeWaitTimeout
	return ctConfig, nil
}

func coreClient(cfg string) (kubernetes.Interface, error) {
	restConfig, err := clientcmd.BuildConfigFromFlags("", cfg)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(restConfig)
}

// Run sets up cgroups, configures the LB proxy, and triggers startup
// of containerd and kubelet. It will only return in case of error or context
// cancellation.
func (a *Agent) Run(ctx context.Context) error {
	if err := cgroups.Validate(); err != nil {
		return err
	}

	proxy, err := a.createProxyAndValidateToken(ctx)
	if err != nil {
		return err
	}

	return a.run(ctx, proxy)
}

func (a *Agent) createProxyAndValidateToken(ctx context.Context) (proxy.Proxy, error) {
	agentDir := filepath.Join(a.AgentConfig.DataDir, "agent")
	if err := os.MkdirAll(agentDir, 0700); err != nil {
		return nil, err
	}

	proxy, err := proxy.NewSupervisorProxy(ctx, !a.AgentConfig.DisableLoadBalancer, agentDir, a.AgentConfig.ServerURL, a.AgentConfig.LBServerPort)
	if err != nil {
		return nil, err
	}

	for {
		newToken, err := clientaccess.ParseAndValidateTokenForUser(proxy.SupervisorURL(), a.AgentConfig.Token, "node")
		if err != nil {
			logrus.Error(err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		a.AgentConfig.Token = newToken.String()
		break
	}
	return proxy, nil
}

func configureNode(ctx context.Context, agentConfig *daemonconfig.Agent, nodes typedcorev1.NodeInterface) error {
	logrus.Infof("default parser: %#v", agentConfig.DefaultParser)
	fieldSelector := fields.Set{metav1.ObjectNameField: agentConfig.NodeName}.String()
	watch, err := nodes.Watch(ctx, metav1.ListOptions{FieldSelector: fieldSelector})
	if err != nil {
		return err
	}
	defer watch.Stop()

	for ev := range watch.ResultChan() {
		node, ok := ev.Object.(*corev1.Node)
		if !ok {
			return fmt.Errorf("could not convert event object to node: %v", ev)
		}

		updateNode := false
		if labels, changed := updateMutableLabels(agentConfig, node.Labels); changed {
			node.Labels = labels
			updateNode = true
		}

		if !agentConfig.DisableCCM {
			if annotations, changed := updateAddressAnnotations(agentConfig, node.Annotations); changed {
				node.Annotations = annotations
				updateNode = true
			}
			if labels, changed := updateLegacyAddressLabels(agentConfig, node.Labels); changed {
				node.Labels = labels
				updateNode = true
			}
		}

		// inject node config
		if changed, err := nodeconfig.SetNodeConfigAnnotations(node, agentConfig.DefaultParser); err != nil {
			return err
		} else if changed {
			updateNode = true
		}

		if updateNode {
			if _, err := nodes.Update(ctx, node, metav1.UpdateOptions{}); err != nil {
				logrus.Infof("Failed to update node %s: %v", agentConfig.NodeName, err)
				continue
			}
			logrus.Infof("labels have been set successfully on node: %s", agentConfig.NodeName)
		} else {
			logrus.Infof("labels have already set on node: %s", agentConfig.NodeName)
		}

		break
	}

	return nil
}

func updateMutableLabels(agentConfig *daemonconfig.Agent, nodeLabels map[string]string) (map[string]string, bool) {
	result := map[string]string{}

	for _, m := range agentConfig.NodeLabels {
		var (
			v string
			p = strings.SplitN(m, `=`, 2)
			k = p[0]
		)
		if len(p) > 1 {
			v = p[1]
		}
		result[k] = v
	}
	result = labels.Merge(nodeLabels, result)
	return result, !equality.Semantic.DeepEqual(nodeLabels, result)
}

func updateLegacyAddressLabels(agentConfig *daemonconfig.Agent, nodeLabels map[string]string) (map[string]string, bool) {
	ls := labels.Set(nodeLabels)
	if ls.Has(cp.InternalIPKey) || ls.Has(cp.HostnameKey) {
		result := map[string]string{
			cp.InternalIPKey: agentConfig.NodeIPStr,
			cp.HostnameKey:   agentConfig.NodeName,
		}

		if agentConfig.NodeExternalIPStr != "" {
			result[cp.ExternalIPKey] = agentConfig.NodeExternalIPStr
		}

		result = labels.Merge(nodeLabels, result)
		return result, !equality.Semantic.DeepEqual(nodeLabels, result)
	}
	return nil, false
}

func updateAddressAnnotations(agentConfig *daemonconfig.Agent, nodeAnnotations map[string]string) (map[string]string, bool) {
	result := map[string]string{
		cp.InternalIPKey: util.JoinIPs(agentConfig.NodeIPs),
		cp.HostnameKey:   agentConfig.NodeName,
	}

	if agentConfig.NodeExternalIPStr != "" {
		result[cp.ExternalIPKey] = util.JoinIPs(agentConfig.NodeExternalIPs)
	}

	result = labels.Merge(nodeAnnotations, result)
	return result, !equality.Semantic.DeepEqual(nodeAnnotations, result)
}

// setupTunnelAndRunAgent should start the setup tunnel before starting kubelet and kubeproxy
// there are special case for etcd agents, it will wait until it can find the apiaddress from
// the address channel and update the proxy with the servers addresses, if in rke2 we need to
// start the agent before the tunnel is setup to allow kubelet to start first and start the pods
func setupTunnelAndRunAgent(ctx context.Context, nodeConfig *daemonconfig.Node, proxy proxy.Proxy) error {
	var agentRan bool
	// IsAPIServerLBEnabled is used as a shortcut for detecting RKE2, where the kubelet needs to
	// be run earlier in order to manage static pods. This should probably instead query a
	// flag on the executor or something.
	if nodeConfig.AgentConfig.ETCDAgent {
		// ETCDAgent is only set to true on servers that are started with --disable-apiserver.
		// In this case, we may be running without an apiserver available in the cluster, and need
		// to wait for one to register and post it's address into APIAddressCh so that we can update
		// the LB proxy with its address.
		if proxy.IsAPIServerLBEnabled() {
			// On RKE2, the agent needs to be started early to run the etcd static pod.
			if err := agent.Agent(ctx, nodeConfig, proxy); err != nil {
				return err
			}
			agentRan = true
		}
		if err := waitForAPIServerAddresses(ctx, nodeConfig, proxy); err != nil {
			return err
		}
	} else if nodeConfig.AgentConfig.ClusterReset && proxy.IsAPIServerLBEnabled() {
		// If we're doing a cluster-reset on RKE2, the kubelet needs to be started early to clean
		// up static pods.
		if err := agent.Agent(ctx, nodeConfig, proxy); err != nil {
			return err
		}
		agentRan = true
	}

	if err := tunnel.Setup(ctx, nodeConfig, proxy); err != nil {
		return err
	}
	if !agentRan {
		return agent.Agent(ctx, nodeConfig, proxy)
	}
	return nil
}

func waitForAPIServerAddresses(ctx context.Context, nodeConfig *daemonconfig.Node, proxy proxy.Proxy) error {
	for {
		select {
		case <-time.After(5 * time.Second):
			logrus.Info("Waiting for apiserver addresses")
		case addresses := <-nodeConfig.AgentConfig.APIAddressCh:
			for i, a := range addresses {
				host, _, err := net.SplitHostPort(a)
				if err == nil {
					addresses[i] = net.JoinHostPort(host, strconv.Itoa(nodeConfig.ServerHTTPSPort))
					if i == 0 {
						proxy.SetSupervisorDefault(addresses[i])
					}
				}
			}
			proxy.Update(addresses)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
