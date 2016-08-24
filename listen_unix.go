// +build linux darwin dragonfly freebsd netbsd openbsd

package main

import (
	"net"

	"github.com/funny/reuseport"
)

func listen() (net.Listener, error) {
	if cfgReusePort {
		return reuseport.NewReusablePortListener("tcp", cfgGatewayAddr)
	}
	return net.Listen("tcp", cfgGatewayAddr)
}
