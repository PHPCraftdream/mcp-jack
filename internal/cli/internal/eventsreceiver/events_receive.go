package eventsreceiver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/wire"
	"github.com/PHPCraftdream/mcp-jack/webhook"
)

const (
	configLimit = 16384
	stateLimit  = 1 << 24
)

type receipt struct {
	SubscriptionID string          `json:"subscription_id"`
	WebhookID      string          `json:"webhook_id"`
	Kind           string          `json:"kind"`
	Message        json.RawMessage `json:"message"`
}

type subscription struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	CallbackURL string `json:"callback_url"`
}
type config struct {
	Version               int               `json:"version"`
	Listen                string            `json:"listen"`
	TLSCertFile           string            `json:"tls_cert_file"`
	TLSKeyFile            string            `json:"tls_key_file"`
	CallbackPath          string            `json:"callback_path"`
	StateFile             string            `json:"state_file"`
	Subscriptions         []subscription    `json:"subscriptions"`
	EnforceServerIdentity bool              `json:"enforce_server_identity"`
	MCPServerKID          string            `json:"mcp_server_kid"`
	MCPServerPublicKey    string            `json:"mcp_server_public_key"`
	ServerKeys            []json.RawMessage `json:"server_keys"`
	MCPURL                string            `json:"mcp_url"`
	CardURL               string            `json:"card_url"`
	WebhookKeyCheck       json.RawMessage   `json:"webhook_key_check,omitempty"`
	JackAudience          string            `json:"jack_audience"`
	AllowPendingSecret    bool              `json:"allow_pending_secret"`
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	return eventsReceive(ctx, args, out)
}

func eventsReceive(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("events receive", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "")
	listen := fs.String("listen", "", "")
	cert := fs.String("tls-cert", "", "")
	key := fs.String("tls-key", "", "")
	callback := fs.String("callback-path", "", "")
	var subscriptionIDs stringList
	fs.Var(&subscriptionIDs, "subscription", "")
	jackAudience := fs.String("jack-audience", "", "")
	mcpServerKID := fs.String("mcp-server-kid", "", "")
	mcpServerPublicKey := fs.String("mcp-server-public-key", "", "")
	serverKeysFile := fs.String("server-keys", "", "")
	mcpURL := fs.String("mcp-url", "", "")
	cardURL := fs.String("card-url", "", "")
	webhookKeyCheckFile := fs.String("webhook-key-check", "", "")
	httpTest := fs.Bool("loopback-http-test", false, "")
	allowPendingSecret := fs.Bool("allow-pending-secret", false, "")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *cfgPath == "" {
		return command.ErrConfig
	}
	var c config
	e := storage.DecodeConfig(*cfgPath, &c)
	if e != nil || c.Version != 1 {
		return command.ErrConfig
	}
	if bytes.Equal(bytes.TrimSpace(c.WebhookKeyCheck), []byte("null")) {
		c.WebhookKeyCheck = nil
	}
	if *allowPendingSecret {
		c.AllowPendingSecret = true
	}
	if *listen != "" {
		c.Listen = *listen
	}
	if *cert != "" {
		c.TLSCertFile = *cert
	}
	if *key != "" {
		c.TLSKeyFile = *key
	}
	if *callback != "" {
		c.CallbackPath = *callback
	}
	if len(subscriptionIDs) != 0 {
		selected := make(map[string]bool, len(subscriptionIDs))
		for _, id := range subscriptionIDs {
			if id == "" || selected[id] {
				return command.ErrConfig
			}
			selected[id] = true
		}
		filtered := make([]subscription, 0, len(selected))
		for _, item := range c.Subscriptions {
			if selected[item.ID] {
				filtered = append(filtered, item)
				delete(selected, item.ID)
			}
		}
		if len(selected) != 0 || len(filtered) == 0 {
			return command.ErrConfig
		}
		c.Subscriptions = filtered
	}
	if *jackAudience != "" {
		c.JackAudience = *jackAudience
	}
	if *mcpServerKID != "" {
		c.MCPServerKID = *mcpServerKID
	}
	if *mcpServerPublicKey != "" {
		c.MCPServerPublicKey = *mcpServerPublicKey
	}
	if *mcpURL != "" {
		c.MCPURL = *mcpURL
	}
	if *cardURL != "" {
		c.CardURL = *cardURL
	}
	if *serverKeysFile != "" {
		data, er := storage.ReadPrivate(*serverKeysFile, configLimit)
		if er != nil || json.Unmarshal(data, &c.ServerKeys) != nil {
			return command.ErrConfig
		}
	}
	if *webhookKeyCheckFile != "" {
		data, er := storage.ReadPrivate(*webhookKeyCheckFile, configLimit)
		if er != nil {
			return command.ErrConfig
		}
		c.WebhookKeyCheck = json.RawMessage(data)
	}
	if e = validate(&c, *httpTest); e != nil {
		return e
	}
	if !*httpTest {
		if _, e = tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); e != nil {
			return command.ErrConfig
		}
		if _, e = storage.ReadPrivate(c.TLSKeyFile, 1<<20); e != nil {
			return command.ErrConfig
		}
	}
	unlock, e := storage.LockState(c.StateFile)
	if e != nil {
		return e
	}
	defer unlock()
	stateInfo, stateErr := os.Lstat(c.StateFile)
	if os.IsNotExist(stateErr) {
		if e = storage.Exclusive(c.StateFile, nil); e != nil {
			return command.ErrConfig
		}
	} else if stateErr != nil || !stateInfo.Mode().IsRegular() {
		return command.ErrConfig
	}
	stateData, e := storage.ReadPrivate(c.StateFile, stateLimit)
	if e != nil {
		return command.ErrConfig
	}
	receipts, e := loadReceipts(stateData)
	if e != nil {
		return command.ErrConfig
	}
	previouslyAccepted, previouslyTerminated := restoreReceiverState(stateData)
	f, e := os.OpenFile(c.StateFile, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return command.ErrConfig
	}
	defer f.Close()
	secrets := make([]webhook.Secret, 0, len(c.Subscriptions))
	routed := make([]string, 0, len(c.Subscriptions))
	callbacks := make(map[string]string)
	for _, s := range c.Subscriptions {
		if s.ID == "" {
			if !c.AllowPendingSecret || s.Secret == "" || s.CallbackURL == "" {
				return command.ErrConfig
			}
			raw, er := webhook.SecretKey(s.Secret)
			if er != nil {
				return command.ErrConfig
			}
			secrets = append(secrets, webhook.Secret{SubscriptionID: "", Key: raw})
			callbacks[""] = s.CallbackURL
			continue
		}
		raw, er := webhook.SecretKey(s.Secret)
		if er != nil {
			return command.ErrConfig
		}
		secrets = append(secrets, webhook.Secret{SubscriptionID: s.ID, Key: raw})
		routed = append(routed, s.ID)
		if s.CallbackURL != "" {
			callbacks[s.ID] = s.CallbackURL
		}
	}
	var keys webhook.KeySource = webhook.StaticKeySource(nil)
	if len(c.ServerKeys) > 0 {
		parsed, _ := webhook.AcceptJWKSet(c.ServerKeys, webhook.CardOptions{MCPServerKID: c.MCPServerKID, MCPServerPublicKey: c.MCPServerPublicKey})
		keys = webhook.StaticKeySource(parsed)
	}
	var cardSource *webhook.CardSource
	if c.CardURL != "" || c.MCPURL != "" {
		client := webhook.NewDeliveryClient(webhook.DeliveryConfig{})
		src, er := webhook.NewCardSource(webhook.CardSourceConfig{Client: client, MCPURL: c.MCPURL, CardURL: c.CardURL, Options: webhook.CardOptions{MCPServerKID: c.MCPServerKID, MCPServerPublicKey: c.MCPServerPublicKey}})
		if er != nil {
			return command.ErrConfig
		}
		if cardErr := src.Refresh(ctx); cardErr != nil {
			return command.ErrConfig
		}
		cardSource = src
		keys = src
	}
	jackCfg := (*webhook.JackConfig)(nil)
	if c.JackAudience != "" {
		jackCfg = &webhook.JackConfig{Aud: c.JackAudience, CallbackURLs: callbacks}
	}
	r, e := webhook.NewReceiver(webhook.ReceiverConfig{Secrets: secrets, Routed: routed, PreviouslyAccepted: previouslyAccepted, PreviouslyTerminated: previouslyTerminated, Keys: keys, EnforceServerIdentity: c.EnforceServerIdentity, MCPServerKID: c.MCPServerKID, MCPServerPublicKey: c.MCPServerPublicKey, Jack: jackCfg, WebhookKey: webhook.WebhookKeyCheck{Required: len(c.WebhookKeyCheck) > 0, ToolResult: c.WebhookKeyCheck}, Enqueue: func(m webhook.ReceivedMessage) error {
		// The SDK has authenticated and validated this receipt before Enqueue.
		// Persist only previously unseen IDs; SDK ACK semantics remain its own.
		key := receiptKey(m.SubscriptionID, m.WebhookID)
		if receipts[key] {
			return nil
		}
		line, er := json.Marshal(receipt{SubscriptionID: m.SubscriptionID, WebhookID: m.WebhookID, Kind: m.Kind, Message: m.Raw})
		if er != nil || int64(fSize(f))+int64(len(line))+1 > stateLimit {
			return errors.New("enqueue failed")
		}
		line = append(line, '\n')
		n, er := f.Write(line)
		if er != nil || n != len(line) || f.Sync() != nil {
			return errors.New("enqueue failed")
		}
		receipts[key] = true
		if m.Kind == "event" {
			output, er := json.Marshal(struct {
				SubscriptionID string          `json:"subscription_id"`
				Event          json.RawMessage `json:"event"`
			}{m.SubscriptionID, m.Raw})
			if er != nil {
				return errors.New("enqueue failed")
			}
			output = append(output, '\n')
			n, er = out.Write(output)
			if er != nil || n != len(output) {
				return errors.New("enqueue failed")
			}
			if f, ok := out.(interface{ Flush() }); ok {
				f.Flush()
			}
		}
		return nil
	}})
	if e != nil {
		return command.ErrConfig
	}
	if f, ok := out.(interface{ Flush() }); ok {
		f.Flush()
	}
	var refreshCtx context.Context
	var stopRefresh context.CancelFunc
	refreshDone := make(chan struct{})
	close(refreshDone)
	if cardSource != nil {
		refreshCtx, stopRefresh = context.WithCancel(ctx)
		refreshDone = make(chan struct{})
		go refreshServerCard(refreshCtx, cardSource, refreshDone)
		defer func() {
			stopRefresh()
			<-refreshDone
		}()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != c.CallbackPath {
			http.NotFound(w, req)
			return
		}
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		webhook.NewHTTPHandler(r).ServeHTTP(w, req)
	})
	listener, listenErr := net.Listen("tcp", c.Listen)
	if listenErr != nil {
		return command.ErrConfig
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	serveErr := make(chan error, 1)
	go func() {
		if *httpTest {
			serveErr <- server.Serve(listener)
		} else {
			serveErr <- server.ServeTLS(listener, c.TLSCertFile, c.TLSKeyFile)
		}
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case serveErr := <-serveErr:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return command.ErrConfig
	}
}

func loadReceipts(data []byte) (map[string]bool, error) {
	loaded := make(map[string]bool)
	if len(data) > stateLimit {
		return nil, command.ErrConfig
	}
	if len(data) == 0 {
		return loaded, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, command.ErrConfig
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), stateLimit)
	for scanner.Scan() {
		line := scanner.Bytes()
		if _, err := wire.Object(line); err != nil {
			return nil, command.ErrConfig
		}
		var r receipt
		decoder := json.NewDecoder(strings.NewReader(string(line)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || r.WebhookID == "" || (r.Kind != "event" && r.Kind != "gap" && r.Kind != "terminated") || len(r.Message) == 0 || !json.Valid(r.Message) {
			return nil, command.ErrConfig
		}
		key := receiptKey(r.SubscriptionID, r.WebhookID)
		if loaded[key] {
			return nil, command.ErrConfig
		}
		loaded[key] = true
	}
	if scanner.Err() != nil {
		return nil, command.ErrConfig
	}
	return loaded, nil
}

func restoreReceiverState(data []byte) (accepted, terminated []string) {
	var records []receipt
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var item receipt
		_ = json.Unmarshal([]byte(line), &item) // loadReceipts has already validated every record.
		records = append(records, item)
	}
	seenIDs, seenTerminated := make(map[string]bool), make(map[string]bool)
	for _, item := range records {
		if !seenIDs[item.WebhookID] {
			accepted = append(accepted, item.WebhookID)
			seenIDs[item.WebhookID] = true
		}
		if item.Kind == "terminated" && !seenTerminated[item.SubscriptionID] {
			terminated = append(terminated, item.SubscriptionID)
			seenTerminated[item.SubscriptionID] = true
		}
	}
	return accepted, terminated
}

func receiptKey(_, webhookID string) string {
	return webhookID
}

func fSize(f *os.File) int64 {
	info, err := f.Stat()
	if err != nil {
		return stateLimit
	}
	return info.Size()
}

func refreshServerCard(ctx context.Context, source *webhook.CardSource, done chan<- struct{}) {
	defer close(done)
	interval := source.TTL() / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > time.Hour {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = source.Refresh(refreshCtx)
			cancel()
		}
	}
}

func validate(c *config, httpTest bool) error {
	if c.Listen == "" || c.CallbackPath == "" || c.StateFile == "" || !filepath.IsAbs(c.StateFile) || !strings.HasPrefix(c.CallbackPath, "/") || c.CallbackPath == "/" || strings.ContainsAny(c.CallbackPath, "?#") {
		return command.ErrConfig
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return command.ErrConfig
	}
	ip := net.ParseIP(host)
	if httpTest {
		if ip == nil || !ip.IsLoopback() || c.TLSCertFile != "" || c.TLSKeyFile != "" {
			return command.ErrConfig
		}
	} else if c.TLSCertFile == "" || c.TLSKeyFile == "" || !filepath.IsAbs(c.TLSCertFile) || !filepath.IsAbs(c.TLSKeyFile) {
		return command.ErrConfig
	}
	if c.EnforceServerIdentity && len(c.ServerKeys) == 0 && c.CardURL == "" {
		return command.ErrConfig
	}
	if c.CardURL != "" && c.MCPURL == "" {
		return command.ErrConfig
	}
	if len(c.Subscriptions) == 0 {
		return command.ErrConfig
	}
	seen := map[string]bool{}
	seenPending := false
	for _, s := range c.Subscriptions {
		if s.ID == "" {
			if !c.AllowPendingSecret || s.Secret == "" || s.CallbackURL == "" || seenPending {
				return command.ErrConfig
			}
			seenPending = true
			continue
		}
		if s.Secret == "" || seen[s.ID] {
			return command.ErrConfig
		}
		seen[s.ID] = true
	}
	return nil
}
