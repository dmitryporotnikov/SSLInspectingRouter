//go:build linux

package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const soOriginalDst = 80

type sockaddrIn struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// getOriginalDestination returns the original destination address/port before
// iptables REDIRECT was applied.
func getOriginalDestination(conn net.Conn) (string, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", 0, fmt.Errorf("connection is not TCP")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return "", 0, fmt.Errorf("syscall conn: %w", err)
	}

	var addr sockaddrIn
	var sockErr error

	controlErr := rawConn.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			sockErr = errno
		}
	})
	if controlErr != nil {
		return "", 0, fmt.Errorf("raw control: %w", controlErr)
	}
	if sockErr != nil {
		return "", 0, fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", sockErr)
	}
	if addr.Family != syscall.AF_INET {
		return "", 0, fmt.Errorf("unsupported address family %d", addr.Family)
	}

	portBytes := *(*[2]byte)(unsafe.Pointer(&addr.Port))
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid destination port %d", port)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	if ip == nil || ip.Equal(net.IPv4zero) {
		return "", 0, fmt.Errorf("invalid destination IP")
	}

	return ip.String(), port, nil
}
