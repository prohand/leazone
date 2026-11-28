package control

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func setPeerFn(f func(net.Conn) (int, error)) {
	peerMu.Lock()
	peerFn = f
	peerMu.Unlock()
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// A socket directory writable by other users (e.g. /tmp) is refused by the
// server and by the client: another user could put its own socket there.
func TestSharedDirectoryRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "leazone.sock")
	if err := Serve(context.Background(), path, func(context.Context, Request) Response { return Response{OK: true} }, discard()); err == nil {
		t.Fatal("server listens in a directory writable by others")
	}
	if _, err := Call(path, Request{Cmd: "ping"}, time.Second); err == nil {
		t.Fatal("client trusts a directory writable by others")
	}
}

// A directory of another user is refused (unless we are root).
func TestForeignDirectoryRefused(t *testing.T) {
	dir := t.TempDir()
	fi, _ := os.Stat(dir)
	owner, _ := ownerUID(fi)
	if owner == 0 {
		t.Skip("directory owned by root: trusted by everyone")
	}
	geteuid = func() int { return owner + 1 }
	defer func() { geteuid = os.Geteuid }()
	if _, err := checkDir(filepath.Join(dir, "leazone.sock")); err == nil {
		t.Fatal("directory of another user accepted")
	}
}

func TestTrustedPeerRules(t *testing.T) {
	defer func() { geteuid = os.Geteuid }()
	geteuid = func() int { return 1000 }
	if !trustedPeer(1000, 1000) || !trustedPeer(0, 1000) || trustedPeer(1001, 1001) {
		t.Fatal("user 1000")
	}
	geteuid = func() int { return 0 }
	if !trustedPeer(1000, 1000) || trustedPeer(1000, 1001) {
		t.Fatal("root")
	}
}

// Both sides check the user of the process at the other end.
func TestPeerUserChecked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leazone.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Serve(ctx, path, func(context.Context, Request) Response { return Response{OK: true, Message: "pong"} }, discard()); err != nil {
		t.Fatal(err)
	}
	// The kernel reports our own user for our own server.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := peerUID(conn)
	conn.Close()
	if err != nil || uid != os.Geteuid() {
		t.Fatalf("peer uid %d %v", uid, err)
	}
	// A server (and a client) of another user is refused.
	defer setPeerFn(peerUID)
	setPeerFn(func(net.Conn) (int, error) { return 4242, nil })
	if os.Geteuid() == 4242 {
		t.Skip("unexpected test user")
	}
	if _, err := Call(path, Request{Cmd: "ping"}, time.Second); err == nil {
		t.Fatal("client talked to a server of another user")
	}
	// Client side trusts again, server side still sees a foreign client.
	var serverChecked atomic.Bool
	setPeerFn(func(c net.Conn) (int, error) {
		if a := c.LocalAddr().String(); a == "" || a == "@" { // client side (unnamed): its server is ours
			return os.Geteuid(), nil
		}
		serverChecked.Store(true)
		return 4242, nil
	})
	// The server writes its refusal and closes at once: depending on timing,
	// the client reads that refusal or fails to write its request (broken
	// pipe). Either way it must never get an answer.
	resp, err := Call(path, Request{Cmd: "ping"}, time.Second)
	if (err == nil && resp.OK) || !serverChecked.Load() {
		t.Fatalf("server answered a client of another user: %+v %v", resp, err)
	}
}
