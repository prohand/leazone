//go:build !linux

package control

import (
	"errors"
	"net"
	"os"
)

func peerUID(net.Conn) (int, error) {
	return -1, errors.New("vérification du processus pair non prise en charge sur ce système")
}

func ownerUID(os.FileInfo) (int, bool) { return -1, false }
