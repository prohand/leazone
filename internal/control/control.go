// Package control is a tiny JSON protocol on a local Unix socket, used by
// CLI sub-commands (healthcheck, admin reset-mfa...) run with "docker exec".
// Only processes running as the same user can open the socket (mode 0600).
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

// Serve listens on path until ctx is done.
func Serve(ctx context.Context, path string, h Handler, log *slog.Logger) error {
	_ = os.Remove(path) // stale socket from a previous run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("control socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
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
			go handle(ctx, conn, h)
		}
	}()
	return nil
}

func handle(ctx context.Context, conn net.Conn, h Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Message: "bad request"})
		return
	}
	_ = json.NewEncoder(conn).Encode(h(ctx, req))
}

// Call sends one request and waits for the answer.
func Call(path string, req Request, timeout time.Duration) (Response, error) {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach the running Leazone process (%s): %w", path, err)
	}
	defer conn.Close()
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
