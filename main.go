package main

import (
	"os"

	"github.com/rancher/rke2/pkg/cli/cert"
	"github.com/rancher/rke2/pkg/cli/cmds"
	"github.com/rancher/rke2/pkg/cli/etcdsnapshot"
	"github.com/rancher/rke2/pkg/configfilearg"
	"github.com/rancher/rke2/pkg/configfilearg/defaultparser"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	serverCmd := cmds.NewServerCommand(cmds.ServerRun)
	agentCmd := cmds.NewAgentCommand(cmds.AgentRun)
	etcdSnapshotCmd := cmds.NewEtcdSnapshotCommand(etcdsnapshot.Run,
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

	if err := app.Run(configfilearg.MustParse(os.Args, defaultparser.DefaultParser)); err != nil {
		logrus.Fatal(err)
	}
}

func addDefaultParser(cmds ...cli.Command) {
	for _, cmd := range cmds {
		defaultparser.DefaultParser.ValidFlags[cmd.Name] = cmd.Flags
	}
}
