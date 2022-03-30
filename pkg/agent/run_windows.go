//go:build windows
// +build windows

package agent

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/rancher/rke2/pkg/config"
)

const (
	dockershimSock = "npipe:////./pipe/docker_engine"
	containerdSock = "npipe:////./pipe/containerd-containerd"
)

// setupCriCtlConfig creates the crictl config file and populates it
// with the given data from config.
func setupCriCtlConfig(nodeConfig *config.Node, dataDir string) error {
	cre := nodeConfig.ContainerRuntimeEndpoint
	if cre == "" || strings.HasPrefix(cre, "npipe:") {
		cre = containerdSock
	}
	agentConfDir := filepath.Join(DataDir, "agent", "etc")
	if _, err := os.Stat(agentConfDir); os.IsNotExist(err) {
		if err := os.MkdirAll(agentConfDir, 0700); err != nil {
			return err
		}
	}

	crp := "runtime-endpoint: " + cre + "\n"
	return ioutil.WriteFile(filepath.Join(agentConfDir, "crictl.yaml"), []byte(crp), 0600)
}
