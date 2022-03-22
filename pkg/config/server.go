package config

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rancher/wrangler/pkg/generated/controllers/core"
	"github.com/urfave/cli"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

type Server struct {
	AdvertiseIP              string
	AdvertisePort            int
	AgentTokenFile           string
	AgentToken               string
	APIServerBindAddress     string
	APIServerPort            int
	BindAddress              string
	ClusterCIDR              cli.StringSlice
	ClusterDNS               cli.StringSlice
	ClusterDomain            string
	ClusterInit              bool
	ClusterReset             bool
	ClusterResetRestorePath  string
	DataDir                  string
	DatastoreCAFile          string
	DatastoreCertFile        string
	Datastore                EndpointConfig
	DatastoreEndpoint        string
	DatastoreKeyFile         string
	DefaultLocalStoragePath  string
	DisableAgent             bool
	DisableAPIServer         bool
	DisableCCM               bool
	DisableControllerManager bool
	DisableETCD              bool
	DisableHelmController    bool
	DisableKubeProxy         bool
	DisableNPC               bool
	DisableScheduler         bool
	Disables                 map[string]bool
	EncryptForce             bool
	EncryptSecrets           bool
	EncryptSkip              bool
	EtcdDisableSnapshots     bool
	EtcdExposeMetrics        bool
	EtcdS3AccessKey          string
	EtcdS3                   bool
	EtcdS3BucketName         string
	EtcdS3EndpointCA         string
	EtcdS3Endpoint           string
	EtcdS3Folder             string
	EtcdS3Insecure           bool
	EtcdS3Region             string
	EtcdS3SecretKey          string
	EtcdS3SkipSSLVerify      bool
	EtcdS3Timeout            time.Duration
	EtcdSnapshotCompress     bool
	EtcdSnapshotCron         string
	EtcdSnapshotDir          string
	EtcdSnapshotName         string
	EtcdSnapshotRetention    int
	ExtraAPIArgs             cli.StringSlice
	ExtraCloudControllerArgs cli.StringSlice
	ExtraControllerArgs      cli.StringSlice
	ExtraEtcdArgs            cli.StringSlice
	ExtraSchedulerArgs       cli.StringSlice
	FlannelBackend           string
	FlannelIPv6Masq          bool
	HTTPSPort                int
	IPSECPSK                 string
	KubeConfigMode           string
	KubeConfigOutput         string
	NoLeaderElect            bool
	PrivateIP                string
	Rootless                 bool
	SANs                     []string
	ServerNodeName           string
	ServerURL                string
	ServiceCIDR              cli.StringSlice
	ServiceNodePortRange     *utilnet.PortRange
	ServiceNodePortRangeStr  string
	Skips                    map[string]bool
	StartupHooks             []StartupHook
	SupervisorPort           int
	SystemDefaultRegistry    string
	TLSCipherSuites          []uint16
	TLSMinVersion            uint16
	TLSSan                   cli.StringSlice
	TokenFile                string
	Token                    string

	LeaderControllers CustomControllers
	Controllers       CustomControllers
	CriticalControlArgs
	Runtime *ControlRuntime `json:"-"`
}

type CriticalControlArgs struct {
	ClusterDNSIPs         []net.IP
	ClusterIPRanges       []*net.IPNet
	ClusterDNSIP          net.IP
	ClusterDomain         string
	ClusterIPRange        *net.IPNet
	DisableCCM            bool
	DisableHelmController bool
	DisableNPC            bool
	DisableServiceLB      bool
	NoCoreDNS             bool
	ServiceIPRange        *net.IPNet
	ServiceIPRanges       []*net.IPNet
}

type ControlRuntimeBootstrap struct {
	ETCDServerCA       string
	ETCDServerCAKey    string
	ETCDPeerCA         string
	ETCDPeerCAKey      string
	ServerCA           string
	ServerCAKey        string
	ClientCA           string
	ClientCAKey        string
	ServiceKey         string
	PasswdFile         string
	RequestHeaderCA    string
	RequestHeaderCAKey string
	IPSECKey           string
	EncryptionConfig   string
	EncryptionHash     string
}

type ControlRuntime struct {
	ControlRuntimeBootstrap

	HTTPBootstrap                       bool
	APIServerReady                      <-chan struct{}
	AgentReady                          <-chan struct{}
	ETCDReady                           <-chan struct{}
	ClusterControllerStart              func(ctx context.Context) error
	LeaderElectedClusterControllerStart func(ctx context.Context) error

	ClientKubeAPICert string
	ClientKubeAPIKey  string
	NodePasswdFile    string

	KubeConfigAdmin           string
	KubeConfigController      string
	KubeConfigScheduler       string
	KubeConfigAPIServer       string
	KubeConfigCloudController string

	ServingKubeAPICert string
	ServingKubeAPIKey  string
	ServingKubeletKey  string
	ServerToken        string
	AgentToken         string
	APIServer          http.Handler
	Handler            http.Handler
	Tunnel             http.Handler
	Authenticator      authenticator.Request

	ClientAuthProxyCert string
	ClientAuthProxyKey  string

	ClientAdminCert           string
	ClientAdminKey            string
	ClientControllerCert      string
	ClientControllerKey       string
	ClientSchedulerCert       string
	ClientSchedulerKey        string
	ClientKubeProxyCert       string
	ClientKubeProxyKey        string
	ClientKubeletKey          string
	ClientCloudControllerCert string
	ClientCloudControllerKey  string
	ClientK3sControllerCert   string
	ClientK3sControllerKey    string

	ServerETCDCert           string
	ServerETCDKey            string
	PeerServerClientETCDCert string
	PeerServerClientETCDKey  string
	ClientETCDCert           string
	ClientETCDKey            string

	Core       *core.Factory
	EtcdConfig ETCDConfig
}

type StartupHookArgs struct {
	APIServerReady  <-chan struct{}
	KubeConfigAdmin string
	Skips           map[string]bool
	Disables        map[string]bool
}

type CustomControllers []func(ctx context.Context, sc *Context) error

type StartupHook func(context.Context, *sync.WaitGroup, StartupHookArgs) error
