//go:build !linux

package proxy

import (
	"fmt"
	"net"
)

func getOriginalDestination(_ net.Conn) (string, int, error) {
	return "", 0, fmt.Errorf("SO_ORIGINAL_DST is only supported on Linux")
}
