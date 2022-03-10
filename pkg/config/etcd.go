package config

import (
	"crypto/tls"

	"github.com/k3s-io/kine/pkg/drivers/generic"
	"google.golang.org/grpc"
)

type EndpointConfig struct {
	GRPCServer           *grpc.Server
	Listener             string
	Endpoint             string
	ConnectionPoolConfig generic.ConnectionPoolConfig
	ServerTLSConfig      tls.Config
	BackendTLSConfig     tls.Config
}

type ETCDConfig struct {
	Endpoints   []string
	TLSConfig   tls.Config
	LeaderElect bool
}
