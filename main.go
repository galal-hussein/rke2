package main

import (
	"os"

	"github.com/k3s-io/k3s/pkg/cli/cert"
	"github.com/k3s-io/k3s/pkg/cli/etcdsnapshot"
	"github.com/k3s-io/k3s/pkg/configfilearg"
	"github.com/rancher/rke2/pkg/cli/cmds"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	serverCmd := cmds.NewServerCommand(cmds.ServerRun)
	agentCmd := cmds.NewAgentCommand(cmds.AgentRun)
	etcdSnapshotCmd := cmds.NewEtcdSnapshotCommand(cmds.EtcdSnapshotRun,
		cmds.NewEtcdSnapshotSubcommands(
			etcdsnapshot.Delete,
			etcdsnapshot.List,
			etcdsnapshot.Prune,
			etcdsnapshot.Run),
	)
	certCmd := cmds.NewCertCommand(
		cmds.NewCertSubcommands(
			cert.Run),
	)
	secretEncryptCmd := cmds.NewSecretsEncryptCommand()
	addDefaultParser(serverCmd, agentCmd, etcdSnapshotCmd, certCmd, secretEncryptCmd)

	app := cmds.NewApp()
	app.Commands = []cli.Command{
		serverCmd,
		agentCmd,
		etcdSnapshotCmd,
		certCmd,
		secretEncryptCmd,
	}

	if err := app.Run(configfilearg.MustParse(os.Args)); err != nil {
		logrus.Fatal(err)
	}
}

func addDefaultParser(cmds ...cli.Command) {
	for _, cmd := range cmds {
		configfilearg.DefaultParser.ValidFlags[cmd.Name] = cmd.Flags
	}
}
