package server

import (
	"context"
	"fmt"
	"io/ioutil"
	net2 "net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k3s-io/helm-controller/pkg/helm"
	"github.com/pkg/errors"
	"github.com/rancher/k3s/pkg/apiaddresses"
	"github.com/rancher/k3s/pkg/clientaccess"
	"github.com/rancher/k3s/pkg/daemons/control"
	"github.com/rancher/k3s/pkg/datadir"
	"github.com/rancher/k3s/pkg/deploy"
	"github.com/rancher/k3s/pkg/node"
	"github.com/rancher/k3s/pkg/nodepassword"
	"github.com/rancher/k3s/pkg/secretsencrypt"
	"github.com/rancher/k3s/pkg/servicelb"
	"github.com/rancher/k3s/pkg/static"
	"github.com/rancher/k3s/pkg/util"
	"github.com/rancher/k3s/pkg/version"
	"github.com/rancher/rke2/pkg/config"
	v1 "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/pkg/leader"
	"github.com/rancher/wrangler/pkg/resolvehome"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/net"
)

const (
	MasterRoleLabelKey       = "node-role.kubernetes.io/master"
	ControlPlaneRoleLabelKey = "node-role.kubernetes.io/control-plane"
	ETCDRoleLabelKey         = "node-role.kubernetes.io/etcd"
)

func ResolveDataDir(dataDir string) (string, error) {
	dataDir, err := datadir.Resolve(dataDir)
	return filepath.Join(dataDir, "server"), err
}

func (s *Server) StartServer(ctx context.Context) error {
	if err := s.setupDataDirAndChdir(); err != nil {
		return err
	}

	if err := s.setNoProxyEnv(); err != nil {
		return err
	}

	// this will need repackaging
	if err := control.Server(ctx, &s.ServerConfig); err != nil {
		return errors.Wrap(err, "starting kubernetes")
	}

	wg := &sync.WaitGroup{}
	wg.Add(len(s.ServerConfig.StartupHooks))

	s.ServerConfig.Runtime.Handler = s.router(ctx)
	shArgs := config.StartupHookArgs{
		APIServerReady:  s.ServerConfig.Runtime.APIServerReady,
		KubeConfigAdmin: s.ServerConfig.Runtime.KubeConfigAdmin,
		Skips:           s.ServerConfig.Skips,
		Disables:        s.ServerConfig.Disables,
	}
	for _, hook := range s.ServerConfig.StartupHooks {
		if err := hook(ctx, wg, shArgs); err != nil {
			return errors.Wrap(err, "startup hook")
		}
	}

	if s.ServerConfig.DisableAPIServer {
		go setETCDLabelsAndAnnotations(ctx, s.ServerConfig)
	} else {
		go s.startOnAPIServerReady(ctx, wg)
	}

	ip := net2.ParseIP(s.ServerConfig.BindAddress)
	if ip == nil {
		hostIP, err := net.ChooseHostInterface()
		if err == nil {
			ip = hostIP
		} else {
			ip = net2.ParseIP("127.0.0.1")
		}
	}

	if err := s.printTokens(ip.String()); err != nil {
		return err
	}

	return s.writeKubeConfig(s.ServerConfig.Runtime.ServerCA)
}

func (s *Server) startOnAPIServerReady(ctx context.Context, wg *sync.WaitGroup) {
	select {
	case <-ctx.Done():
		return
	case <-s.ServerConfig.Runtime.APIServerReady:
		if err := s.runControllers(ctx, wg); err != nil {
			logrus.Fatalf("failed to start controllers: %v", err)
		}
	}
}

func (s *Server) runControllers(ctx context.Context, wg *sync.WaitGroup) error {
	config := s.ServerConfig
	sc, err := NewContext(ctx, config.Runtime.KubeConfigAdmin)
	if err != nil {
		return errors.Wrap(err, "failed to create new server context")
	}

	wg.Wait()
	if err := s.stageFiles(ctx, sc); err != nil {
		return errors.Wrap(err, "failed to stage files")
	}

	// run migration before we set controlConfig.Runtime.Core
	if err := nodepassword.MigrateFile(
		sc.Core.Core().V1().Secret(),
		sc.Core.Core().V1().Node(),
		config.Runtime.NodePasswdFile); err != nil {
		logrus.Warn(errors.Wrap(err, "error migrating node-password file"))
	}
	config.Runtime.Core = sc.Core

	if config.Runtime.ClusterControllerStart != nil {
		if err := config.Runtime.ClusterControllerStart(ctx); err != nil {
			return errors.Wrap(err, "failed to start cluster controllers")
		}
	}

	for _, controller := range config.Controllers {
		if err := controller(ctx, sc); err != nil {
			return errors.Wrapf(err, "failed to start custom controller %s", util.GetFunctionName(controller))
		}
	}

	if err := sc.Start(ctx); err != nil {
		return errors.Wrap(err, "failed to start wranger controllers")
	}

	start := func(ctx context.Context) {
		if err := s.coreControllers(ctx, sc); err != nil {
			panic(err)
		}
		if config.Runtime.LeaderElectedClusterControllerStart != nil {
			if err := config.Runtime.LeaderElectedClusterControllerStart(ctx); err != nil {
				panic(errors.Wrap(err, "failed to start leader elected cluster controllers"))
			}
		}
		for _, controller := range config.LeaderControllers {
			if err := controller(ctx, sc); err != nil {
				panic(errors.Wrap(err, "leader controller"))
			}
		}
		if err := sc.Start(ctx); err != nil {
			panic(err)
		}
	}

	go s.setNodeLabelsAndAnnotations(ctx, sc.Core.Core().V1().Node())

	go s.setClusterDNSConfig(ctx, sc.Core.Core().V1().ConfigMap())

	if config.NoLeaderElect {
		go func() {
			start(ctx)
			<-ctx.Done()
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				logrus.Fatalf("controllers exited: %v", err)
			}
		}()
	} else {
		go leader.RunOrDie(ctx, "", version.Program, sc.K8s, start)
	}

	return nil
}

func (s *Server) coreControllers(ctx context.Context, sc *Context) error {
	if err := node.Register(ctx,
		!s.ServerConfig.Skips["coredns"],
		sc.Core.Core().V1().Secret(),
		sc.Core.Core().V1().ConfigMap(),
		sc.Core.Core().V1().Node()); err != nil {
		return err
	}

	// apply SystemDefaultRegistry setting to Helm and ServiceLB before starting controllers
	if s.ServerConfig.SystemDefaultRegistry != "" {
		helm.DefaultJobImage = s.ServerConfig.SystemDefaultRegistry + "/" + helm.DefaultJobImage
		servicelb.DefaultLBImage = s.ServerConfig.SystemDefaultRegistry + "/" + servicelb.DefaultLBImage
	}

	if !s.ServerConfig.DisableHelmController {
		helm.Register(ctx,
			sc.Apply,
			sc.Helm.Helm().V1().HelmChart(),
			sc.Helm.Helm().V1().HelmChartConfig(),
			sc.Batch.Batch().V1().Job(),
			sc.Auth.Rbac().V1().ClusterRoleBinding(),
			sc.Core.Core().V1().ServiceAccount(),
			sc.Core.Core().V1().ConfigMap())
	}

	if err := apiaddresses.Register(ctx, s.ServerConfig.Runtime, sc.Core.Core().V1().Endpoints()); err != nil {
		return err
	}

	if s.ServerConfig.EncryptSecrets {
		if err := secretsencrypt.Register(ctx,
			sc.K8s,
			&s.ServerConfig,
			sc.Core.Core().V1().Node(),
			sc.Core.Core().V1().Secret()); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) stageFiles(ctx context.Context, sc *Context) error {
	dataDir := filepath.Join(s.ServerConfig.DataDir, "static")
	if err := static.Stage(dataDir); err != nil {
		return err
	}
	dataDir = filepath.Join(s.ServerConfig.DataDir, "manifests")
	templateVars := map[string]string{
		"%{CLUSTER_DNS}%":                 s.ServerConfig.ClusterDNSIP.String(),
		"%{CLUSTER_DOMAIN}%":              s.ServerConfig.ClusterDomain,
		"%{DEFAULT_LOCAL_STORAGE_PATH}%":  s.ServerConfig.DefaultLocalStoragePath,
		"%{SYSTEM_DEFAULT_REGISTRY}%":     registryTemplate(s.ServerConfig.SystemDefaultRegistry),
		"%{SYSTEM_DEFAULT_REGISTRY_RAW}%": s.ServerConfig.SystemDefaultRegistry,
	}

	skip := s.ServerConfig.Skips
	if !skip["traefik"] && isHelmChartTraefikV1(sc) {
		logrus.Warn("Skipping Traefik v2 deployment due to existing Traefik v1 installation")
		skip["traefik"] = true
	}
	if err := deploy.Stage(dataDir, templateVars, skip); err != nil {
		return err
	}

	return deploy.WatchFiles(ctx,
		sc.K8s,
		sc.Apply,
		sc.K3s.K3s().V1().Addon(),
		s.ServerConfig.Disables,
		dataDir)
}

// registryTemplate behaves like the system_default_registry template in Rancher helm charts,
// and returns the registry value with a trailing forward slash if the registry string is not empty.
// If it is empty, it is passed through as a no-op.
func registryTemplate(registry string) string {
	if registry == "" {
		return registry
	}
	return registry + "/"
}

// isHelmChartTraefikV1 checks for an existing HelmChart resource with spec.chart containing traefik-1,
// as deployed by the legacy chart (https://%{KUBERNETES_API}%/static/charts/traefik-1.81.0.tgz)
func isHelmChartTraefikV1(sc *Context) bool {
	prefix := "traefik-1."
	helmChart, err := sc.Helm.Helm().V1().HelmChart().Get(metav1.NamespaceSystem, "traefik", metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Info("Failed to get existing traefik HelmChart")
		return false
	}
	chart := path.Base(helmChart.Spec.Chart)
	if strings.HasPrefix(chart, prefix) {
		logrus.WithField("chart", chart).Info("Found existing traefik v1 HelmChart")
		return true
	}
	return false
}

func HomeKubeConfig(write bool) (string, error) {
	if write {
		if os.Getuid() == 0 {
			return datadir.GlobalConfig, nil
		}
		return resolvehome.Resolve(datadir.HomeConfig)
	}

	if _, err := os.Stat(datadir.GlobalConfig); err == nil {
		return datadir.GlobalConfig, nil
	}

	return resolvehome.Resolve(datadir.HomeConfig)
}

func (s *Server) printTokens(advertiseIP string) error {
	var (
		nodeFile string
	)

	if advertiseIP == "" {
		advertiseIP = "127.0.0.1"
	}

	if len(s.ServerConfig.Runtime.ServerToken) > 0 {
		p := filepath.Join(s.ServerConfig.DataDir, "token")
		if err := writeToken(s.ServerConfig.Runtime.ServerToken, p, s.ServerConfig.Runtime.ServerCA); err == nil {
			logrus.Infof("Node token is available at %s", p)
			nodeFile = p
		}

		// backwards compatibility
		np := filepath.Join(s.ServerConfig.DataDir, "node-token")
		if !isSymlink(np) {
			if err := os.RemoveAll(np); err != nil {
				return err
			}
			if err := os.Symlink(p, np); err != nil {
				return err
			}
		}
	}

	if len(nodeFile) > 0 {
		printToken(s.ServerConfig.SupervisorPort, advertiseIP, "To join node to cluster:", "agent")
	}

	return nil
}

func (s *Server) writeKubeConfig(certs string) error {
	ip := s.ServerConfig.BindAddress
	if ip == "" {
		ip = "127.0.0.1"
	}
	url := fmt.Sprintf("https://%s:%d", ip, s.ServerConfig.HTTPSPort)
	kubeConfig, err := HomeKubeConfig(true)
	def := true
	if err != nil {
		kubeConfig = filepath.Join(s.ServerConfig.DataDir, "kubeconfig-"+version.Program+".yaml")
		def = false
	}
	kubeConfigSymlink := kubeConfig
	if s.ServerConfig.KubeConfigOutput != "" {
		kubeConfig = s.ServerConfig.KubeConfigOutput
	}

	if isSymlink(kubeConfigSymlink) {
		if err := os.Remove(kubeConfigSymlink); err != nil {
			logrus.Errorf("Failed to remove kubeconfig symlink")
		}
	}

	if err = clientaccess.WriteClientKubeConfig(kubeConfig, url, s.ServerConfig.Runtime.ServerCA, s.ServerConfig.Runtime.ClientAdminCert,
		s.ServerConfig.Runtime.ClientAdminKey); err == nil {
		logrus.Infof("Wrote kubeconfig %s", kubeConfig)
	} else {
		logrus.Errorf("Failed to generate kubeconfig: %v", err)
		return err
	}

	if s.ServerConfig.KubeConfigMode != "" {
		mode, err := strconv.ParseInt(s.ServerConfig.KubeConfigMode, 8, 0)
		if err == nil {
			util.SetFileModeForPath(kubeConfig, os.FileMode(mode))
		} else {
			logrus.Errorf("Failed to set %s to mode %s: %v", kubeConfig, os.FileMode(mode), err)
		}
	} else {
		util.SetFileModeForPath(kubeConfig, os.FileMode(0600))
	}

	if kubeConfigSymlink != kubeConfig {
		if err := writeConfigSymlink(kubeConfig, kubeConfigSymlink); err != nil {
			logrus.Errorf("Failed to write kubeconfig symlink: %v", err)
		}
	}

	if def {
		logrus.Infof("Run: %s kubectl", filepath.Base(os.Args[0]))
	}

	return nil
}

func (s *Server) setupDataDirAndChdir() error {
	var (
		err error
	)

	s.ServerConfig.DataDir, err = ResolveDataDir(s.ServerConfig.DataDir)
	if err != nil {
		return err
	}

	dataDir := s.ServerConfig.DataDir

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return errors.Wrapf(err, "can not mkdir %s", dataDir)
	}

	if err := os.Chdir(dataDir); err != nil {
		return errors.Wrapf(err, "can not chdir %s", dataDir)
	}

	return nil
}

func printToken(httpsPort int, advertiseIP, prefix, cmd string) {
	ip := advertiseIP
	if ip == "" {
		hostIP, err := net.ChooseHostInterface()
		if err != nil {
			logrus.Errorf("Failed to choose interface: %v", err)
		}
		ip = hostIP.String()
	}

	logrus.Infof("%s %s %s -s https://%s:%d -t ${NODE_TOKEN}", prefix, version.Program, cmd, ip, httpsPort)
}

func writeToken(token, file, certs string) error {
	if len(token) == 0 {
		return nil
	}

	token, err := clientaccess.FormatToken(token, certs)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, []byte(token+"\n"), 0600)
}

func (s *Server) setNoProxyEnv() error {
	splitter := func(c rune) bool {
		return c == ','
	}
	envList := []string{}
	envList = append(envList, strings.FieldsFunc(os.Getenv("NO_PROXY"), splitter)...)
	envList = append(envList, strings.FieldsFunc(os.Getenv("no_proxy"), splitter)...)
	envList = append(envList,
		".svc",
		"."+s.ServerConfig.ClusterDomain,
		util.JoinIPNets(s.ServerConfig.ClusterIPRanges),
		util.JoinIPNets(s.ServerConfig.ServiceIPRanges),
	)
	os.Unsetenv("no_proxy")
	return os.Setenv("NO_PROXY", strings.Join(envList, ","))
}

func writeConfigSymlink(kubeconfig, kubeconfigSymlink string) error {
	if err := os.Remove(kubeconfigSymlink); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s file: %v", kubeconfigSymlink, err)
	}
	if err := os.MkdirAll(filepath.Dir(kubeconfigSymlink), 0755); err != nil {
		return fmt.Errorf("failed to create path for symlink: %v", err)
	}
	if err := os.Symlink(kubeconfig, kubeconfigSymlink); err != nil {
		return fmt.Errorf("failed to create symlink: %v", err)
	}
	return nil
}

func isSymlink(config string) bool {
	if fi, err := os.Lstat(config); err == nil && (fi.Mode()&os.ModeSymlink == os.ModeSymlink) {
		return true
	}
	return false
}

func (s *Server) setNodeLabelsAndAnnotations(ctx context.Context, nodes v1.NodeClient) error {
	if s.ServerConfig.DisableAgent || s.ServerConfig.DisableAPIServer {
		return nil
	}
	for {
		nodeName := os.Getenv("NODE_NAME")
		if nodeName == "" {
			logrus.Info("Waiting for control-plane node agent startup")
			time.Sleep(1 * time.Second)
			continue
		}
		node, err := nodes.Get(nodeName, metav1.GetOptions{})
		if err != nil {
			logrus.Infof("Waiting for control-plane node %s startup: %v", nodeName, err)
			time.Sleep(1 * time.Second)
			continue
		}
		// remove etcd label if etcd is disabled
		var etcdRoleLabelExists bool
		if s.ServerConfig.DisableETCD {
			if _, ok := node.Labels[ETCDRoleLabelKey]; ok {
				delete(node.Labels, ETCDRoleLabelKey)
				etcdRoleLabelExists = true
			}
		}
		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		v, ok := node.Labels[ControlPlaneRoleLabelKey]
		if !ok || v != "true" || etcdRoleLabelExists {
			node.Labels[ControlPlaneRoleLabelKey] = "true"
			node.Labels[MasterRoleLabelKey] = "true"
		}

		if s.ServerConfig.EncryptSecrets {
			if err = secretsencrypt.BootstrapEncryptionHashAnnotation(node, s.ServerConfig.Runtime); err != nil {
				logrus.Infof("Unable to set encryption hash annotation %s", err.Error())
				break
			}
		}

		_, err = nodes.Update(node)
		if err == nil {
			logrus.Infof("Labels and annotations have been set successfully on node: %s", nodeName)
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil
}

func (s *Server) setClusterDNSConfig(ctx context.Context, configMap v1.ConfigMapClient) error {
	// check if configmap already exists
	_, err := configMap.Get("kube-system", "cluster-dns", metav1.GetOptions{})
	if err == nil {
		logrus.Infof("Cluster dns configmap already exists")
		return nil
	}
	clusterDNS := s.ServerConfig.ClusterDNSIP
	clusterDomain := s.ServerConfig.ClusterDomain
	c := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-dns",
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"clusterDNS":    clusterDNS.String(),
			"clusterDomain": clusterDomain,
		},
	}
	for {
		_, err = configMap.Create(c)
		if err == nil {
			logrus.Infof("Cluster dns configmap has been set successfully")
			break
		}
		logrus.Infof("Waiting for control-plane dns startup: %v", err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil
}
