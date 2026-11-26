package control

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The socket is private (0600) as soon as it is reachable at its path.
func TestServeSocketMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leazone.sock")
	ctx, cancel := context.WithCancel(context.Background())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := Serve(ctx, path, func(context.Context, Request) Response { return Response{OK: true, Message: "pong"} }, log)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", fi.Mode(), err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary directory left behind: %v", entries)
	}
	resp, err := Call(path, Request{Cmd: "ping"}, time.Second)
	if err != nil || !resp.OK || resp.Message != "pong" {
		t.Fatalf("call: %+v %v", resp, err)
	}
	cancel()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket not removed at shutdown")
}
