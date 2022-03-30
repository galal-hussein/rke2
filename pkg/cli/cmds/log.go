package cmds

import (
	"github.com/rancher/rke2/pkg/log"
	"github.com/rancher/rke2/pkg/version"
	"github.com/urfave/cli"
)

var (
	DebugFlag = cli.BoolFlag{
		Name:        "debug",
		Usage:       "(logging) Turn on debug logs",
		Destination: &log.LogConfig.Debug,
		EnvVar:      version.ProgramUpper + "_DEBUG",
	}
	VLevel = cli.IntFlag{
		Name:        "v",
		Usage:       "(logging) Number for the log level verbosity",
		Destination: &log.LogConfig.VLevel,
	}
	VModule = cli.StringFlag{
		Name:        "vmodule",
		Usage:       "(logging) Comma-separated list of pattern=N settings for file-filtered logging",
		Destination: &log.LogConfig.VModule,
	}
	LogFile = cli.StringFlag{
		Name:        "log,l",
		Usage:       "(logging) Log to file",
		Destination: &log.LogConfig.LogFile,
	}
	AlsoLogToStderr = cli.BoolFlag{
		Name:        "alsologtostderr",
		Usage:       "(logging) Log to standard error as well as file (if set)",
		Destination: &log.LogConfig.AlsoLogToStderr,
	}
)
