package config

type Agent struct {
	Token                    string
	TokenFile                string
	ClusterSecret            string
	ServerURL                string
	APIAddressCh             chan string
	DisableLoadBalancer      bool
	DisableServiceLB         bool
	ETCDAgent                bool
	LBServerPort             int
	ResolvConf               string
	DataDir                  string
	NodeIP                   []string
	NodeExternalIP           []string
	NodeName                 string
	PauseImage               string
	Snapshotter              string
	Docker                   bool
	ContainerRuntimeEndpoint string
	NoFlannel                bool
	FlannelIface             string
	FlannelConf              string
	Debug                    bool
	WithNodeID               bool
	EnableSELinux            bool
	ProtectKernelDefaults    bool
	ClusterReset             bool
	PrivateRegistry          string
	SystemDefaultRegistry    string
	AirgapExtraRegistry      []string
	ExtraKubeletArgs         []string
	ExtraKubeProxyArgs       []string
	Labels                   []string
	Taints                   []string
	ImageCredProvBinDir      string
	ImageCredProvConfig      string
	AgentReady               chan<- struct{}
	AgentShared
}

type AgentShared struct {
	NodeIP string
}
