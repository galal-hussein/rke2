package version

import "strings"

var (
	Program      = "rke2"
	ProgramUpper = strings.ToUpper(Program)
	Version      = "dev"
	GitCommit    = "HEAD"
)
