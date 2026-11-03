package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// webhook is a stand-in Discord that answers each request with the next status in statuses (the
// last repeats) and records the bodies it was sent.
func webhook(t *testing.T, header http.Header, statuses ...int) (*Discord, *atomic.Int32, chan discordBody) {
	t.Helper()
	var calls atomic.Int32
	bodies := make(chan discordBody, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		var b discordBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("body is not JSON: %v", err)
		}
		bodies <- b
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(statuses[min(n, len(statuses))-1])
	}))
	t.Cleanup(srv.Close)
	d, err := NewDiscord(srv.URL+"/api/webhooks/1/secret-token", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	d.backoff = 10 * time.Millisecond
	return d, &calls, bodies
}

func TestDiscord_PostsOneEmbedWithMentionsOff(t *testing.T) {
	t.Parallel()
	d, _, bodies := webhook(t, nil, http.StatusNoContent)
	err := d.Notify(context.Background(), Message{
		Title: "New account", URL: "https://console.example/accounts/a1", Text: "@everyone hello",
		Fields: []Field{{Name: "Account", Value: "a1"}, {Name: "Promo", Value: ""}, {Name: "Via", Value: "google"}},
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	b := <-bodies
	if len(b.Embeds) != 1 {
		t.Fatalf("embeds = %d, want 1", len(b.Embeds))
	}
	e := b.Embeds[0]
	if e.Title != "New account" || e.URL != "https://console.example/accounts/a1" || e.Description != "@everyone hello" {
		t.Errorf("embed = %+v", e)
	}
	if len(e.Fields) != 2 || e.Fields[0].Name != "Account" || e.Fields[1].Value != "google" {
		t.Errorf("fields = %+v, want Account and Via (the empty Promo left out)", e.Fields)
	}
	if b.AllowedMentions.Parse == nil || len(b.AllowedMentions.Parse) != 0 {
		t.Errorf("allowed_mentions.parse = %v, want an empty list so nothing pings", b.AllowedMentions.Parse)
	}
}

func TestDiscord_CutsToDiscordsLimits(t *testing.T) {
	t.Parallel()
	fields := make([]Field, 30)
	for i := range fields {
		fields[i] = Field{Name: "n", Value: strings.Repeat("v", 2000)}
	}
	b := discordPayload(Message{Title: strings.Repeat("é", 300), Fields: fields})
	e := b.Embeds[0]
	if n := len([]rune(e.Title)); n != maxTitle || !strings.HasSuffix(e.Title, "…") {
		t.Errorf("title is %d characters, want %d ending in an ellipsis", n, maxTitle)
	}
	if len(e.Fields) != maxFields || len([]rune(e.Fields[0].Value)) != maxFieldValue {
		t.Errorf("fields = %d of %d characters, want %d of %d", len(e.Fields), len([]rune(e.Fields[0].Value)), maxFields, maxFieldValue)
	}
}

func TestDiscord_Retries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		header   http.Header
		statuses []int
		wantErr  bool
		calls    int32
	}{
		{"rate limited, then sent", http.Header{"Retry-After": {"0.01"}}, []int{429, 204}, false, 2},
		{"server errors, then sent", nil, []int{502, 503, 204}, false, 3},
		{"server errors every time", nil, []int{500}, true, attempts},
		{"refused: not retried", nil, []int{400}, true, 1},
		{"rate limited past the wait: not retried", http.Header{"Retry-After": {"60"}}, []int{429}, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, calls, _ := webhook(t, tt.header, tt.statuses...)
			err := d.Notify(context.Background(), Message{Title: "t"})
			if (err != nil) != tt.wantErr {
				t.Errorf("Notify = %v, want error %v", err, tt.wantErr)
			}
			if got := calls.Load(); got != tt.calls {
				t.Errorf("requests = %d, want %d", got, tt.calls)
			}
		})
	}
}

// The webhook URL is its secret: a failed request must not repeat it.
func TestDiscord_ErrorsNeverCarryTheWebhookURL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listening: the request fails in the transport
	d, err := NewDiscord(srv.URL+"/api/webhooks/1/secret-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	d.backoff = time.Millisecond
	err = d.Notify(context.Background(), Message{Title: "t"})
	if err == nil {
		t.Fatal("Notify succeeded with nothing listening")
	}
	if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error %q carries the webhook URL", err)
	}
}

func TestNewDiscord_RefusesWhatIsNotAURL(t *testing.T) {
	t.Parallel()
	for _, u := range []string{"", "discord.com/api/webhooks/1/x", "ftp://discord.com/x", "https://"} {
		if _, err := NewDiscord(u, nil); err == nil {
			t.Errorf("NewDiscord(%q) succeeded", u)
		} else if u != "" && strings.Contains(err.Error(), u) {
			t.Errorf("error %q repeats the URL", err)
		}
	}
}

func TestDiscord_StopsWhenTheContextEnds(t *testing.T) {
	t.Parallel()
	d, _, _ := webhook(t, http.Header{"Retry-After": {"5"}}, 429)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := d.Notify(ctx, Message{Title: "t"}); err == nil {
		t.Fatal("Notify succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Notify kept waiting after its context ended")
	}
}
