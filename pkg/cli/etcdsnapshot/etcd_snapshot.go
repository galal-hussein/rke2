package etcdsnapshot

// import (
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"os"
// 	"path/filepath"
// 	"strings"
// 	"text/tabwriter"
// 	"time"

// 	"github.com/erikdubbelboer/gspt"
// 	"github.com/rancher/rke2/pkg/cli/cmds"
// 	"github.com/rancher/rke2/pkg/cluster"
// 	"github.com/rancher/rke2/pkg/daemons/config"
// 	"github.com/rancher/rke2/pkg/etcd"
// 	"github.com/rancher/rke2/pkg/log"
// 	"github.com/rancher/rke2/pkg/server"
// 	util2 "github.com/rancher/rke2/pkg/util"
// 	"github.com/rancher/wrangler/pkg/signals"
// 	"github.com/urfave/cli"
// 	"gopkg.in/yaml.v2"
// )

// // commandSetup setups up common things needed
// // for each etcd command.
// func commandSetup(app *cli.Context, cfg *config.Server) error {
// 	gspt.SetProcTitle(os.Args[0])

// 	nodeName := app.String("node-name")
// 	if nodeName == "" {
// 		h, err := os.Hostname()
// 		if err != nil {
// 			return err
// 		}
// 		nodeName = h
// 	}

// 	os.Setenv("NODE_NAME", nodeName)

// 	dataDir, err := server.ResolveDataDir(cfg.DataDir)
// 	if err != nil {
// 		return err
// 	}

// 	cfg.DisableAgent = true
// 	cfg.ControlConfig.DataDir = dataDir
// 	cfg.ControlConfig.EtcdSnapshotName = cfg.EtcdSnapshotName
// 	cfg.ControlConfig.EtcdSnapshotDir = cfg.EtcdSnapshotDir
// 	cfg.ControlConfig.EtcdSnapshotCompress = cfg.EtcdSnapshotCompress
// 	cfg.ControlConfig.EtcdListFormat = strings.ToLower(cfg.EtcdListFormat)
// 	cfg.ControlConfig.EtcdS3 = cfg.EtcdS3
// 	cfg.ControlConfig.EtcdS3Endpoint = cfg.EtcdS3Endpoint
// 	cfg.ControlConfig.EtcdS3EndpointCA = cfg.EtcdS3EndpointCA
// 	cfg.ControlConfig.EtcdS3SkipSSLVerify = cfg.EtcdS3SkipSSLVerify
// 	cfg.ControlConfig.EtcdS3AccessKey = cfg.EtcdS3AccessKey
// 	cfg.ControlConfig.EtcdS3SecretKey = cfg.EtcdS3SecretKey
// 	cfg.ControlConfig.EtcdS3BucketName = cfg.EtcdS3BucketName
// 	cfg.ControlConfig.EtcdS3Region = cfg.EtcdS3Region
// 	cfg.ControlConfig.EtcdS3Folder = cfg.EtcdS3Folder
// 	cfg.ControlConfig.EtcdS3Insecure = cfg.EtcdS3Insecure
// 	cfg.ControlConfig.EtcdS3Timeout = cfg.EtcdS3Timeout
// 	cfg.ControlConfig.Runtime = &config.ControlRuntime{}
// 	cfg.ControlConfig.Runtime.ETCDServerCA = filepath.Join(dataDir, "tls", "etcd", "server-ca.crt")
// 	cfg.ControlConfig.Runtime.ClientETCDCert = filepath.Join(dataDir, "tls", "etcd", "client.crt")
// 	cfg.ControlConfig.Runtime.ClientETCDKey = filepath.Join(dataDir, "tls", "etcd", "client.key")
// 	cfg.ControlConfig.Runtime.KubeConfigAdmin = filepath.Join(dataDir, "cred", "admin.kubeconfig")

// 	return nil
// }

// // Run is an alias for Save, retained for compatibility reasons.
// func Run(app *cli.Context) error {
// 	return Save(app)
// }

// // Save triggers an on-demand etcd snapshot operation
// func Save(app *cli.Context) error {
// 	if err := log.InitLogging(); err != nil {
// 		return err
// 	}
// 	return save(app, &cmds.ServerConfig)
// }

// func save(app *cli.Context, cfg *config.Server) error {
// 	var serverConfig server.Config

// 	if err := commandSetup(app, cfg, &serverConfig); err != nil {
// 		return err
// 	}

// 	if len(app.Args()) > 0 {
// 		return util2.ErrCommandNoArgs
// 	}

// 	serverConfig.ControlConfig.EtcdSnapshotRetention = 0 // disable retention check

// 	ctx := signals.SetupSignalContext()
// 	e := etcd.NewETCD()
// 	if err := e.SetControlConfig(ctx, &serverConfig.ControlConfig); err != nil {
// 		return err
// 	}

// 	initialized, err := e.IsInitialized(ctx, &serverConfig.ControlConfig)
// 	if err != nil {
// 		return err
// 	}
// 	if !initialized {
// 		return fmt.Errorf("etcd database not found in %s", serverConfig.ControlConfig.DataDir)
// 	}

// 	cluster := cluster.New(&serverConfig.ControlConfig)

// 	if err := cluster.Bootstrap(ctx, true); err != nil {
// 		return err
// 	}

// 	sc, err := server.NewContext(ctx, serverConfig.ControlConfig.Runtime.KubeConfigAdmin)
// 	if err != nil {
// 		return err
// 	}
// 	serverConfig.ControlConfig.Runtime.Core = sc.Core

// 	return cluster.Snapshot(ctx, &serverConfig.ControlConfig)
// }

// func Delete(app *cli.Context) error {
// 	if err := cmds.InitLogging(); err != nil {
// 		return err
// 	}
// 	return delete(app, &cmds.ServerConfig)
// }

// func delete(app *cli.Context, cfg *cmds.Server) error {
// 	var serverConfig server.Config

// 	if err := commandSetup(app, cfg, &serverConfig); err != nil {
// 		return err
// 	}

// 	snapshots := app.Args()
// 	if len(snapshots) == 0 {
// 		return errors.New("no snapshots given for removal")
// 	}

// 	ctx := signals.SetupSignalContext()
// 	e := etcd.NewETCD()
// 	if err := e.SetControlConfig(ctx, &serverConfig.ControlConfig); err != nil {
// 		return err
// 	}

// 	sc, err := server.NewContext(ctx, serverConfig.ControlConfig.Runtime.KubeConfigAdmin)
// 	if err != nil {
// 		return err
// 	}
// 	serverConfig.ControlConfig.Runtime.Core = sc.Core

// 	return e.DeleteSnapshots(ctx, app.Args())
// }

// func List(app *cli.Context) error {
// 	if err := cmds.InitLogging(); err != nil {
// 		return err
// 	}
// 	return list(app, &cmds.ServerConfig)
// }

// var etcdListFormats = []string{"json", "yaml"}

// func validEtcdListFormat(format string) bool {
// 	for _, supportedFormat := range etcdListFormats {
// 		if format == supportedFormat {
// 			return true
// 		}
// 	}
// 	return false
// }

// func list(app *cli.Context, cfg *cmds.Server) error {
// 	var serverConfig server.Config

// 	if err := commandSetup(app, cfg, &serverConfig); err != nil {
// 		return err
// 	}

// 	ctx := signals.SetupSignalContext()
// 	e := etcd.NewETCD()
// 	if err := e.SetControlConfig(ctx, &serverConfig.ControlConfig); err != nil {
// 		return err
// 	}

// 	sf, err := e.ListSnapshots(ctx)
// 	if err != nil {
// 		return err
// 	}

// 	if cfg.EtcdListFormat != "" && !validEtcdListFormat(cfg.EtcdListFormat) {
// 		return errors.New("invalid output format: " + cfg.EtcdListFormat)
// 	}

// 	switch cfg.EtcdListFormat {
// 	case "json":
// 		if err := json.NewEncoder(os.Stdout).Encode(sf); err != nil {
// 			return err
// 		}
// 		return nil
// 	case "yaml":
// 		if err := yaml.NewEncoder(os.Stdout).Encode(sf); err != nil {
// 			return err
// 		}
// 		return nil
// 	default:
// 		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
// 		defer w.Flush()

// 		if cfg.EtcdS3 {
// 			fmt.Fprint(w, "Name\tSize\tCreated\n")
// 			for _, s := range sf {
// 				if s.NodeName == "s3" {
// 					fmt.Fprintf(w, "%s\t%d\t%s\n", s.Name, s.Size, s.CreatedAt.Format(time.RFC3339))
// 				}
// 			}
// 		} else {
// 			fmt.Fprint(w, "Name\tLocation\tSize\tCreated\n")
// 			for _, s := range sf {
// 				if s.NodeName != "s3" {
// 					fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", s.Name, s.Location, s.Size, s.CreatedAt.Format(time.RFC3339))
// 				}
// 			}
// 		}
// 	}

// 	return nil
// }

// func Prune(app *cli.Context) error {
// 	if err := cmds.InitLogging(); err != nil {
// 		return err
// 	}
// 	return prune(app, &cmds.ServerConfig)
// }

// func prune(app *cli.Context, cfg *cmds.Server) error {
// 	var serverConfig server.Config

// 	if err := commandSetup(app, cfg, &serverConfig); err != nil {
// 		return err
// 	}

// 	serverConfig.ControlConfig.EtcdSnapshotRetention = cfg.EtcdSnapshotRetention

// 	ctx := signals.SetupSignalContext()
// 	e := etcd.NewETCD()
// 	if err := e.SetControlConfig(ctx, &serverConfig.ControlConfig); err != nil {
// 		return err
// 	}

// 	sc, err := server.NewContext(ctx, serverConfig.ControlConfig.Runtime.KubeConfigAdmin)
// 	if err != nil {
// 		return err
// 	}
// 	serverConfig.ControlConfig.Runtime.Core = sc.Core

// 	return e.PruneSnapshots(ctx)
// }
