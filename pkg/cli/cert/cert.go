package cert

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/erikdubbelboer/gspt"
	"github.com/otiai10/copy"
	"github.com/rancher/rke2/pkg/config"
	"github.com/rancher/rke2/pkg/daemons/control/deps"
	"github.com/rancher/rke2/pkg/datadir"
	"github.com/rancher/rke2/pkg/log"
	"github.com/rancher/rke2/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	adminService             = "admin"
	apiServerService         = "api-server"
	controllerManagerService = "controller-manager"
	schedulerService         = "scheduler"
	etcdService              = "etcd"
	programControllerService = "-controller"
	authProxyService         = "auth-proxy"
	cloudControllerService   = "cloud-controller"
	kubeletService           = "kubelet"
	kubeProxyService         = "kube-proxy"
	k3sServerService         = "-server"
)

var services = []string{
	adminService,
	apiServerService,
	controllerManagerService,
	schedulerService,
	etcdService,
	version.Program + programControllerService,
	authProxyService,
	cloudControllerService,
	kubeletService,
	kubeProxyService,
	version.Program + k3sServerService,
}

func commandSetup(app *cli.Context, cfg *config.Server) (string, string, error) {
	gspt.SetProcTitle(os.Args[0])

	cfg.Runtime = &config.ControlRuntime{}
	dataDir, err := datadir.Resolve(cfg.DataDir)
	if err != nil {
		return "", "", err
	}
	return filepath.Join(dataDir, "server"), filepath.Join(dataDir, "agent"), err
}

func Run(app *cli.Context) error {
	if err := log.InitLogging(); err != nil {
		return err
	}
	return rotate(app, &config.Server)
}

func rotate(app *cli.Context, cfg *config.Server) error {

	serverDataDir, agentDataDir, err := commandSetup(app, cfg)
	if err != nil {
		return err
	}

	cfg.Runtime = &config.ControlRuntime{}
	deps.CreateRuntimeCertFiles(cfg)

	if err := validateCertConfig(); err != nil {
		return err
	}

	tlsBackupDir, err := backupCertificates(serverDataDir, agentDataDir)
	if err != nil {
		return err
	}

	if len(config.ServicesList) == 0 {
		// detecting if the service is an agent or server
		_, err := os.Stat(serverDataDir)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			logrus.Infof("Agent detected, rotating agent certificates")
			config.ServicesList = []string{
				kubeletService,
				kubeProxyService,
				version.Program + programControllerService,
			}
		} else {
			logrus.Infof("Server detected, rotating server certificates")
			config.ServicesList = []string{
				adminService,
				etcdService,
				apiServerService,
				controllerManagerService,
				cloudControllerService,
				schedulerService,
				version.Program + k3sServerService,
				version.Program + programControllerService,
				authProxyService,
				kubeletService,
				kubeProxyService,
			}
		}
	}
	fileList := []string{}
	for _, service := range config.ServicesList {
		logrus.Infof("Rotating certificates for %s service", service)
		switch service {
		case adminService:
			fileList = append(fileList,
				cfg.Runtime.ClientAdminCert,
				cfg.Runtime.ClientAdminKey)
		case apiServerService:
			fileList = append(fileList,
				cfg.Runtime.ClientKubeAPICert,
				cfg.Runtime.ClientKubeAPIKey,
				cfg.Runtime.ServingKubeAPICert,
				cfg.Runtime.ServingKubeAPIKey)
		case controllerManagerService:
			fileList = append(fileList,
				cfg.Runtime.ClientControllerCert,
				cfg.Runtime.ClientControllerKey)
		case schedulerService:
			fileList = append(fileList,
				cfg.Runtime.ClientSchedulerCert,
				cfg.Runtime.ClientSchedulerKey)
		case etcdService:
			fileList = append(fileList,
				cfg.Runtime.ClientETCDCert,
				cfg.Runtime.ClientETCDKey,
				cfg.Runtime.ServerETCDCert,
				cfg.Runtime.ServerETCDKey,
				cfg.Runtime.PeerServerClientETCDCert,
				cfg.Runtime.PeerServerClientETCDKey)
		case cloudControllerService:
			fileList = append(fileList,
				cfg.Runtime.ClientCloudControllerCert,
				cfg.Runtime.ClientCloudControllerKey)
		case version.Program + k3sServerService:
			dynamicListenerRegenFilePath := filepath.Join(serverDataDir, "tls", "dynamic-cert-regenerate")
			if err := ioutil.WriteFile(dynamicListenerRegenFilePath, []byte{}, 0600); err != nil {
				return err
			}
			logrus.Infof("Rotating dynamic listener certificate")
		case version.Program + programControllerService:
			fileList = append(fileList,
				cfg.Runtime.ClientK3sControllerCert,
				cfg.Runtime.ClientK3sControllerKey,
				filepath.Join(agentDataDir, "client-"+version.Program+"-controller.crt"),
				filepath.Join(agentDataDir, "client-"+version.Program+"-controller.key"))
		case authProxyService:
			fileList = append(fileList,
				cfg.Runtime.ClientAuthProxyCert,
				cfg.Runtime.ClientAuthProxyKey)
		case kubeletService:
			fileList = append(fileList,
				cfg.Runtime.ClientKubeletKey,
				cfg.Runtime.ServingKubeletKey,
				filepath.Join(agentDataDir, "client-kubelet.crt"),
				filepath.Join(agentDataDir, "client-kubelet.key"),
				filepath.Join(agentDataDir, "serving-kubelet.crt"),
				filepath.Join(agentDataDir, "serving-kubelet.key"))
		case kubeProxyService:
			fileList = append(fileList,
				cfg.Runtime.ClientKubeProxyCert,
				cfg.Runtime.ClientKubeProxyKey,
				filepath.Join(agentDataDir, "client-kube-proxy.crt"),
				filepath.Join(agentDataDir, "client-kube-proxy.key"))
		default:
			logrus.Fatalf("%s is not a recognized service", service)
		}
	}

	for _, file := range fileList {
		if err := os.Remove(file); err == nil {
			logrus.Debugf("file %s is deleted", file)
		}
	}
	logrus.Infof("Successfully backed up certificates for all services to path %s, please restart %s server or agent to rotate certificates", tlsBackupDir, version.Program)
	return nil
}

func copyFile(src, destDir string) error {
	_, err := os.Stat(src)
	if err == nil {
		input, err := ioutil.ReadFile(src)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(filepath.Join(destDir, filepath.Base(src)), input, 0644)
	} else if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func backupCertificates(serverDataDir, agentDataDir string) (string, error) {
	serverTLSDir := filepath.Join(serverDataDir, "tls")
	tlsBackupDir := filepath.Join(serverDataDir, "tls-"+strconv.Itoa(int(time.Now().Unix())))

	if _, err := os.Stat(serverTLSDir); err != nil {
		return "", err
	}
	if err := copy.Copy(serverTLSDir, tlsBackupDir); err != nil {
		return "", err
	}
	agentCerts := []string{
		filepath.Join(agentDataDir, "client-"+version.Program+"-controller.crt"),
		filepath.Join(agentDataDir, "client-"+version.Program+"-controller.key"),
		filepath.Join(agentDataDir, "client-kubelet.crt"),
		filepath.Join(agentDataDir, "client-kubelet.key"),
		filepath.Join(agentDataDir, "serving-kubelet.crt"),
		filepath.Join(agentDataDir, "serving-kubelet.key"),
		filepath.Join(agentDataDir, "client-kube-proxy.crt"),
		filepath.Join(agentDataDir, "client-kube-proxy.key"),
	}
	for _, cert := range agentCerts {
		if err := copyFile(cert, tlsBackupDir); err != nil {
			return "", err
		}
	}
	return tlsBackupDir, nil
}

func validService(svc string) bool {
	for _, service := range services {
		if svc == service {
			return true
		}
	}
	return false
}

func validateCertConfig() error {
	for _, s := range config.ServicesList {
		if !validService(s) {
			return errors.New("Service " + s + " is not recognized")
		}
	}
	return nil
}
