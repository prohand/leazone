package technitium

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Credentials never travel in the URL: login and token go in a POST form.
func TestSecretsNotInURL(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.String()+" user="+r.PostForm.Get("user")+" pass="+r.PostForm.Get("pass")+" token="+r.PostForm.Get("token"))
		mu.Unlock()
		switch r.URL.Path {
		case "/api/user/login":
			w.Write([]byte(`{"status":"ok","token":"session-tok"}`))
		default:
			w.Write([]byte(`{"status":"error","errorMessage":"stop"}`))
		}
	}))
	defer ts.Close()
	im := &Importer{Client: ts.Client()}
	_, _ = im.Run(context.Background(), Options{URL: ts.URL, Username: "admin", Password: "s3cret-pass"})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("requests: %v", seen)
	}
	for _, s := range seen {
		method, rest, _ := strings.Cut(s, " ")
		url, _, _ := strings.Cut(rest, " ")
		if method != http.MethodPost || strings.Contains(url, "s3cret-pass") || strings.Contains(url, "session-tok") || strings.Contains(url, "?") {
			t.Fatalf("secret or parameters in the URL: %s", s)
		}
	}
	if !strings.Contains(seen[0], "user=admin pass=s3cret-pass") || !strings.Contains(seen[1], "token=session-tok") {
		t.Fatalf("form: %v", seen)
	}
}

type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("boom") }

// A transport error does not show the request URL (nor any secret in it).
func TestErrorHidesSecrets(t *testing.T) {
	im := &Importer{Client: &http.Client{Transport: failing{}}}
	_, err := im.Run(context.Background(), Options{URL: "http://10.0.0.5:5380", Token: "secret-tok"})
	if err == nil || strings.Contains(err.Error(), "secret-tok") || strings.Contains(err.Error(), "http://") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error: %v", err)
	}
}
