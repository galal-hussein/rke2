package configfilearg

import (
	"github.com/rancher/rke2/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func DefaultParser(validFlags map[string][]cli.Flag) *Parser {
	return &Parser{
		After:         []string{"server", "agent", "etcd-snapshot:1"},
		FlagNames:     []string{"--config", "-c"},
		EnvName:       version.ProgramUpper + "_CONFIG_FILE",
		DefaultConfig: "/etc/rancher/" + version.Program + "/config.yaml",
		ValidFlags:    validFlags,
	}
}

func MustParse(args []string, parser *Parser) []string {
	result, err := parser.Parse(args)
	if err != nil {
		logrus.Fatal(err)
	}
	return result
}

func MustFindString(args []string, target string) string {
	parser := &Parser{
		After:         []string{},
		FlagNames:     []string{},
		EnvName:       version.ProgramUpper + "_CONFIG_FILE",
		DefaultConfig: "/etc/rancher/" + version.Program + "/config.yaml",
	}
	result, err := parser.FindString(args, target)
	if err != nil {
		logrus.Fatal(err)
	}
	return result
}
