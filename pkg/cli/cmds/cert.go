package cmds

// import (
// 	"io/ioutil"
// 	"path/filepath"

// 	"github.com/rancher/rke2/pkg/cli/cert"
// 	"github.com/rancher/rke2/pkg/config"
// 	"github.com/rancher/rke2/pkg/version"
// 	"github.com/urfave/cli"
// )

// const CertCommand = "certificate"

// var (
// 	CertCommandFlags = []cli.Flag{
// 		DebugFlag,
// 		ConfigFlag,
// 		LogFile,
// 		AlsoLogToStderr,
// 		cli.StringFlag{
// 			Name:        "data-dir,d",
// 			Usage:       "(data) Folder to hold state default /var/lib/rancher/" + version.Program + " or ${HOME}/.rancher/" + version.Program + " if not root",
// 			Destination: &ServerConfig.DataDir,
// 			Value:       rke2Path,
// 		},
// 		cli.StringSliceFlag{
// 			Name:  "service,s",
// 			Usage: "List of services to rotate certificates for. Options include (admin, api-server, controller-manager, scheduler, " + version.Program + "-controller, " + version.Program + "-server, cloud-controller, etcd, auth-proxy, kubelet, kube-proxy)",
// 			Value: &config.ServicesList,
// 		},
// 	}
// 	certSubcommands = []cli.Command{
// 		{
// 			Name:            "rotate",
// 			Usage:           "Certificate Rotatation",
// 			SkipFlagParsing: false,
// 			SkipArgReorder:  true,
// 			Action:          CertificateRotationRun,
// 			Flags:           CertCommandFlags,
// 		},
// 	}
// )

// func NewCertCommand(subcommands []cli.Command) cli.Command {
// 	return cli.Command{
// 		Name:            CertCommand,
// 		Usage:           "Certificates management",
// 		SkipFlagParsing: false,
// 		SkipArgReorder:  true,
// 		Subcommands:     subcommands,
// 		Flags:           CertCommandFlags,
// 	}
// }

// func NewCertSubcommands(rotate func(ctx *cli.Context) error) []cli.Command {
// 	return []cli.Command{
// 		{
// 			Name:            "rotate",
// 			Usage:           "Certificate rotation",
// 			SkipFlagParsing: false,
// 			SkipArgReorder:  true,
// 			Action:          rotate,
// 			Flags:           CertCommandFlags,
// 		},
// 	}
// }

// func CertificateRotationRun(clx *cli.Context) error {
// 	dataDir := clx.String("data-dir")
// 	if dataDir == "" {
// 		dataDir = rke2Path
// 	}
// 	if err := ioutil.WriteFile(ForceRestartFile(dataDir), []byte{}, 0600); err != nil {
// 		return err
// 	}
// 	return cert.Run(clx)
// }

// func ForceRestartFile(dataDir string) string {
// 	return filepath.Join(dataDir, "force-restart")
// }
