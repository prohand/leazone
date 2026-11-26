package logging

import (
	"context"
	"errors"
	"log/slog"
)

// multi fans out records to several handlers.
type multi []slog.Handler

func (m multi) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m multi) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m {
		if h.Enabled(ctx, r.Level) {
			errs = append(errs, h.Handle(ctx, r.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (m multi) WithAttrs(a []slog.Attr) slog.Handler {
	out := make(multi, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(a)
	}
	return out
}

func (m multi) WithGroup(n string) slog.Handler {
	out := make(multi, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(n)
	}
	return out
}
