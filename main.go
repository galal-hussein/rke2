//go:generate go run pkg/codegen/cleanup/main.go
//go:generate rm -rf pkg/generated
//go:generate go run pkg/codegen/main.go
//go:generate go fmt pkg/deploy/zz_generated_bindata.go
//go:generate go fmt pkg/static/zz_generated_bindata.go
package main

import (
	"os"

	"github.com/rancher/rke2/pkg/cli/cmds"
	"github.com/rancher/rke2/pkg/configfilearg"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	serverCmd := cmds.NewServerCommand(cmds.ServerRun)
	agentCmd := cmds.NewAgentCommand(cmds.AgentRun)
	// etcdSnapshotCmd := cmds.NewEtcdSnapshotCommand(etcdsnapshot.Run,
	// 	cmds.NewEtcdSnapshotSubcommands(
	// 		etcdsnapshot.Delete,
	// 		etcdsnapshot.List,
	// 		etcdsnapshot.Prune,
	// 		etcdsnapshot.Run),
	// )
	// certCmd := cmds.NewCertCommand(
	// 	cmds.NewCertSubcommands(
	// 		cert.Run),
	// )
	// secretEncryptCmd := cmds.NewSecretsEncryptCommand()
	addDefaultParser(serverCmd, agentCmd)

	app := cmds.NewApp()
	app.Commands = []cli.Command{
		serverCmd,
		agentCmd,
		// etcdSnapshotCmd,
		// certCmd,
		// secretEncryptCmd,
	}
	if err := app.Run(configfilearg.MustParse(os.Args, cmds.DefaultParser)); err != nil {
		logrus.Fatal(err)
	}
}

func addDefaultParser(commands ...cli.Command) {
	for _, cmd := range commands {
		cmds.DefaultParser.ValidFlags[cmd.Name] = cmd.Flags
	}
}
