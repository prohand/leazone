// Package control is a tiny JSON protocol on a local Unix socket, used by
// CLI sub-commands (healthcheck, admin reset-mfa...) run with "docker exec".
// Only processes running as the same user can open the socket (mode 0600).
// Both ends check who is on the other side (SO_PEERCRED: same user, or
// root), and the socket directory must be private, so that no other local
// user can stand in for the server (and receive a backup password, say).
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Request is a command sent to the server.
type Request struct {
	Cmd  string            `json:"cmd"`
	Args map[string]string `json:"args,omitempty"`
}

// Response is the server answer.
type Response struct {
	OK      bool           `json:"ok"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

// Handler executes a request.
type Handler func(ctx context.Context, req Request) Response

// geteuid is os.Geteuid (tests change it).
var geteuid = os.Geteuid

// peerFn is peerUID (tests change it, see setPeerFn).
var (
	peerMu sync.Mutex
	peerFn = peerUID
)

func peerOf(c net.Conn) (int, error) {
	peerMu.Lock()
	f := peerFn
	peerMu.Unlock()
	return f(c)
}

// checkDir verifies that nobody but us (or root) can create a socket in the
// directory of path: it must belong to the current user (or root) and be
// writable by nobody else. It returns the owner of the directory.
func checkDir(path string) (int, error) {
	dir := filepath.Dir(path)
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return -1, err
	}
	owner, ok := ownerUID(fi)
	if !ok {
		return -1, fmt.Errorf("propriétaire du dossier %s inconnu", dir)
	}
	me := geteuid()
	if owner != me && owner != 0 && me != 0 {
		return -1, fmt.Errorf("le dossier %s de la socket de contrôle appartient à l'UID %d et non à l'UID courant %d", dir, owner, me)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return -1, fmt.Errorf("le dossier %s de la socket de contrôle est modifiable par d'autres utilisateurs (droits %o) : utilisez un dossier privé (0700)", dir, perm)
	}
	return owner, nil
}

// trustedPeer reports whether the process at the other end of the socket
// may be trusted: same user, root, or (for root) the owner of the directory.
func trustedPeer(peer, dirOwner int) bool {
	me := geteuid()
	return peer == me || peer == 0 || (me == 0 && peer == dirOwner)
}

// Serve listens on path until ctx is done.
func Serve(ctx context.Context, path string, h Handler, log *slog.Logger) error {
	owner, err := checkDir(path)
	if err != nil {
		return fmt.Errorf("control socket %s: %w", path, err)
	}
	_ = os.Remove(path) // stale socket from a previous run
	ln, err := listenPrivate(path)
	if err != nil {
		return fmt.Errorf("control socket %s: %w", path, err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		_ = os.Remove(path)
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Warn("control accept", "err", err)
				continue
			}
			go handle(ctx, conn, h, owner)
		}
	}()
	return nil
}

// listenPrivate creates the socket with mode 0600 from the start: it is
// bound in a fresh 0700 directory, restricted, then moved to path. Binding
// at path directly would leave it open to other users (umask) until a chmod.
func listenPrivate(path string) (net.Listener, error) {
	dir, err := os.MkdirTemp(filepath.Dir(path), ".leazone-control-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, err
	}
	// The socket is removed by Serve at shutdown (it is no longer at tmp).
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func handle(ctx context.Context, conn net.Conn, h Handler, dirOwner int) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if uid, err := peerOf(conn); err != nil || !trustedPeer(uid, dirOwner) {
		_ = json.NewEncoder(conn).Encode(Response{Message: "refusé : client d'un autre utilisateur"})
		return
	}
	var req Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Message: "bad request"})
		return
	}
	_ = json.NewEncoder(conn).Encode(h(ctx, req))
}

// Call sends one request and waits for the answer. It only talks to a
// server of the same user (or root) behind a private directory.
func Call(path string, req Request, timeout time.Duration) (Response, error) {
	owner, err := checkDir(path)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach the running Leazone process (%s): %w", path, err)
	}
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach the running Leazone process (%s): %w", path, err)
	}
	defer conn.Close()
	uid, err := peerOf(conn)
	if err != nil {
		return Response{}, fmt.Errorf("socket de contrôle %s : %w", path, err)
	}
	if !trustedPeer(uid, owner) {
		return Response{}, fmt.Errorf("socket de contrôle %s : le serveur tourne sous l'UID %d, pas sous l'UID %d : refusé", path, uid, geteuid())
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
