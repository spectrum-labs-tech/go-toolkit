package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"
)

// Discord's embed limits (https://discord.com/developers/docs/resources/message#embed-object-embed-limits).
const (
	maxTitle      = 256
	maxText       = 4096
	maxFieldName  = 256
	maxFieldValue = 1024
	maxFields     = 25
)

const (
	attempts = 3
	// maxWait caps how long one Notify waits on a rate limit or an outage before giving up. A
	// caller that must not lose a message keeps it and tries again later.
	maxWait = 10 * time.Second
)

// Discord posts to a Discord channel webhook.
type Discord struct {
	url     string
	client  *http.Client
	backoff time.Duration // the wait after an outage, where Discord names none
}

// NewDiscord returns a Notifier for a channel webhook URL. A nil client means one with a 10-second
// timeout.
func NewDiscord(webhookURL string, client *http.Client) (*Discord, error) {
	u, err := url.Parse(webhookURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		// Not the URL itself: it is the webhook's secret.
		return nil, errors.New("notify: discord webhook URL is not an absolute http(s) URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Discord{url: webhookURL, client: client, backoff: time.Second}, nil
}

// Notify posts m as one embed. Mentions are switched off, so no text in a message can ping a
// channel. It retries a rate limit or a server error a few times, within maxWait.
func (d *Discord) Notify(ctx context.Context, m Message) error {
	body, err := json.Marshal(discordPayload(m))
	if err != nil {
		return fmt.Errorf("notify: discord: %w", err)
	}
	deadline := time.Now().Add(maxWait)
	for attempt := 1; ; attempt++ {
		wait, err := d.post(ctx, body)
		if err == nil {
			return nil
		}
		if wait < 0 || attempt == attempts || time.Now().Add(wait).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// post sends one request. On failure it returns how long to wait before another try, or a
// negative wait when another try would not help.
func (d *Discord) post(ctx context.Context, body []byte) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return -1, errors.New("notify: discord: could not build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		// *url.Error repeats the URL, and with it the webhook's token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return d.backoff, fmt.Errorf("notify: discord: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode < 300:
		return 0, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return retryAfter(resp.Header.Get("Retry-After"), data, d.backoff), fmt.Errorf("notify: discord: rate limited")
	case resp.StatusCode >= 500:
		return d.backoff, fmt.Errorf("notify: discord: HTTP %d", resp.StatusCode)
	default:
		return -1, fmt.Errorf("notify: discord: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(data))
	}
}

// retryAfter reads Discord's wait in seconds, from the header or the JSON body's retry_after.
func retryAfter(header string, body []byte, fallback time.Duration) time.Duration {
	secs, err := strconv.ParseFloat(header, 64)
	if err != nil {
		var b struct {
			RetryAfter float64 `json:"retry_after"`
		}
		if json.Unmarshal(body, &b) != nil || b.RetryAfter <= 0 {
			return fallback
		}
		secs = b.RetryAfter
	}
	return time.Duration(secs * float64(time.Second))
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordEmbed struct {
	Title       string              `json:"title,omitempty"`
	URL         string              `json:"url,omitempty"`
	Description string              `json:"description,omitempty"`
	Fields      []discordEmbedField `json:"fields,omitempty"`
}

type discordBody struct {
	Embeds          []discordEmbed `json:"embeds"`
	AllowedMentions struct {
		Parse []string `json:"parse"`
	} `json:"allowed_mentions"`
}

func discordPayload(m Message) discordBody {
	e := discordEmbed{Title: truncate(m.Title, maxTitle), URL: m.URL, Description: truncate(m.Text, maxText)}
	for _, f := range m.Fields {
		if f.Value == "" || len(e.Fields) == maxFields {
			continue
		}
		e.Fields = append(e.Fields, discordEmbedField{
			Name: truncate(f.Name, maxFieldName), Value: truncate(f.Value, maxFieldValue), Inline: true,
		})
	}
	b := discordBody{Embeds: []discordEmbed{e}}
	b.AllowedMentions.Parse = []string{}
	return b
}

// truncate cuts s to at most n characters, ending in an ellipsis when it cut.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
