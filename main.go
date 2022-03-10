package main

import (
	"os"

	"github.com/k3s-io/k3s/pkg/configfilearg"
	"github.com/rancher/k3s/pkg/cli/cert"
	"github.com/rancher/k3s/pkg/cli/etcdsnapshot"
	"github.com/rancher/k3s/pkg/configfilearg"
	"github.com/rancher/rke2/pkg/cli/cmds"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	app := cmds.NewApp()
	app.Commands = []cli.Command{
		cmds.NewServerCommand(cmds.ServerRun),
		cmds.NewAgentCommand(cmds.AgentRun),
		cmds.NewEtcdSnapshotCommand(cmds.EtcdSnapshotRun,
			cmds.NewEtcdSnapshotSubcommands(
				etcdsnapshot.Delete,
				etcdsnapshot.List,
				etcdsnapshot.Prune,
				etcdsnapshot.Run),
		),
		cmds.NewCertCommand(
			cmds.NewCertSubcommands(
				cert.Run),
		),
		cmds.NewSecretsEncryptCommand(),
	}

	if err := app.Run(configfilearg.MustParse(os.Args)); err != nil {
		logrus.Fatal(err)
	}
}
