package agent

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/erikdubbelboer/gspt"
	"github.com/rancher/rke2/pkg/config"
	"github.com/rancher/rke2/pkg/datadir"
	"github.com/rancher/rke2/pkg/log"
	"github.com/rancher/rke2/pkg/token"
	"github.com/rancher/rke2/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type Agent struct {
	AgentConfig *config.Agent
}

func (a *Agent) Agent(ctx *cli.Context) error {
	// hide process arguments from ps output, since they may contain
	// database credentials or other secrets.
	gspt.SetProcTitle(os.Args[0] + " agent")

	// Evacuate cgroup v2 before doing anything else that may fork.
	if err := EvacuateCgroup2(); err != nil {
		return err
	}

	// Initialize logging, and subprocess reaping if necessary.
	// Log output redirection and subprocess reaping both require forking.
	if err := log.InitLogging(); err != nil {
		return err
	}

	if os.Getuid() != 0 && runtime.GOOS != "windows" {
		return fmt.Errorf("agent must be ran as root")
	}

	if a.AgentConfig.TokenFile != "" {
		token, err := token.ReadFile(a.AgentConfig.TokenFile)
		if err != nil {
			return err
		}
		a.AgentConfig.Token = token
	}

	if a.AgentConfig.Token == "" && a.AgentConfig.ClusterSecret != "" {
		a.AgentConfig.Token = a.AgentConfig.ClusterSecret
	}

	if a.AgentConfig.Token == "" {
		return fmt.Errorf("--token is required")
	}

	if a.AgentConfig.ServerURL == "" {
		return fmt.Errorf("--server is required")
	}

	logrus.Info("Starting " + version.Program + " agent " + ctx.App.Version)

	dataDir, err := datadir.LocalHome(a.AgentConfig.DataDir, a.AgentConfig.Rootless)
	if err != nil {
		return err
	}

	a.AgentConfig.Debug = ctx.GlobalBool("debug")
	a.AgentConfig.DataDir = dataDir

	return a.Run(context.Background())
}
