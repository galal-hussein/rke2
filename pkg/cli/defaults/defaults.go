package defaults

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/rancher/rke2/pkg/config"
	"github.com/urfave/cli"
	"google.golang.org/grpc/grpclog"
)

func Set(clx *cli.Context, serverConfig *config.Server, agentConfig *config.Agent, debug bool) error {
	logsDir := filepath.Join(serverConfig.DataDir, "agent", "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return errors.Wrapf(err, "failed to create directory %s", logsDir)
	}

	serverConfig.DatastoreEndpoint = "etcd"
	serverConfig.DisableNPC = true
	serverConfig.FlannelBackend = "none"
	serverConfig.AdvertisePort = 6443
	serverConfig.SupervisorPort = 9345
	serverConfig.HTTPSPort = 6443
	serverConfig.APIServerPort = 6443
	serverConfig.APIServerBindAddress = "0.0.0.0"
	agentConfig.NoFlannel = true
	serverConfig.ExtraAPIArgs = append(
		[]string{
			"enable-admission-plugins=NodeRestriction,PodSecurityPolicy",
		},
		serverConfig.ExtraAPIArgs...)
	agentConfig.ExtraKubeletArgs = append(
		[]string{
			"stderrthreshold=FATAL",
			"log-file-max-size=50",
			"alsologtostderr=false",
			"logtostderr=false",
			"log-file=" + filepath.Join(logsDir, "kubelet.log"),
		},
		agentConfig.ExtraKubeletArgs...)

	if !debug {
		l := grpclog.NewLoggerV2(ioutil.Discard, ioutil.Discard, os.Stderr)
		grpclog.SetLoggerV2(l)
	}

	return nil
}
