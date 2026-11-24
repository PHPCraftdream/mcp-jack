//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package eventsreceiver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
)

const processHelperEnv = "MCP_JACK_EVENTS_RECEIVER_PROCESS_HELPER"

func TestEventsReceiveSubprocessWritesSignedEventAndAcknowledges(t *testing.T) {
	dir := eventsPrivateDir(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	secret := "whsec_" + base64.StdEncoding.EncodeToString(secretBytes)
	const subscriptionID = "sub_0123456789abcdef"
	const webhookID = "evt_0123456789abcdef"
	const event = `{"data":{},"eventId":"event-123","name":"order.created","timestamp":"2026-11-24T00:00:00Z"}`
	statePath := filepath.Join(dir, "events.jsonl")
	cfg := config{
		Version: 1, Listen: listen, CallbackPath: "/hooks", StateFile: statePath,
		Subscriptions: []subscription{{ID: subscriptionID, Secret: secret}},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "receiver.json")
	if err := storage.Exclusive(configPath, cfgBytes); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestEventsReceiveSubprocessHelper$")
	cmd.Env = append(os.Environ(), processHelperEnv+"=1", "MCP_JACK_EVENTS_RECEIVER_CONFIG="+configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	body := []byte(event)
	timestamp := fmt.Sprint(time.Now().Unix())
	signingInput := append([]byte(webhookID+"."+timestamp+"."), body...)
	mac := hmac.New(sha256.New, secretBytes)
	_, _ = mac.Write(signingInput)
	signature := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	client := &http.Client{Timeout: 2 * time.Second}
	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		request, requestErr := http.NewRequest(http.MethodPost, "http://"+listen+"/hooks", strings.NewReader(string(body)))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Webhook-Id", webhookID)
		request.Header.Set("Webhook-Timestamp", timestamp)
		request.Header.Set("Webhook-Signature", signature)
		request.Header.Set("X-MCP-Subscription-Id", subscriptionID)
		response, err = client.Do(request)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("receiver did not become available: %v; child stderr: %s", err, stderr.String())
	}
	responseBody, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || string(responseBody) != `{"status":"accepted"}` {
		t.Fatalf("response = %d %s, want 200 accepted", response.StatusCode, responseBody)
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+listen+"/hooks", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Webhook-Id", webhookID)
	request.Header.Set("Webhook-Timestamp", timestamp)
	request.Header.Set("Webhook-Signature", signature)
	request.Header.Set("X-MCP-Subscription-Id", subscriptionID)
	duplicate, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	duplicateBody, err := io.ReadAll(duplicate.Body)
	_ = duplicate.Body.Close()
	if err != nil || duplicate.StatusCode != http.StatusOK || string(duplicateBody) != `{"status":"duplicate"}` {
		t.Fatalf("duplicate response = %d %s err=%v, want 200 duplicate", duplicate.StatusCode, duplicateBody, err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("{\"subscription_id\":%q,\"event\":%s}\n", subscriptionID, event)
	if string(output) != want {
		t.Fatalf("JSONL output = %q, want %q", output, want)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("receiver subprocess failed: %v; stderr: %s", err, stderr.String())
	}
	state, err := storage.ReadPrivate(statePath, 1<<20)
	if err != nil {
		t.Fatalf("durable receipt was not privately stored: %v", err)
	}
	if len(bytes.Split(bytes.TrimSpace(state), []byte{'\n'})) != 1 {
		t.Fatalf("receipt log contains wrong number of records: %q", state)
	}
}

func TestEventsReceiveTLSRestartAcknowledgesPersistedDuplicate(t *testing.T) {
	dir := eventsPrivateDir(t)
	certPEM, keyPEM, err := processTLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "receiver.crt"), filepath.Join(dir, "receiver.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := socket.Addr().String()
	_ = socket.Close()
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	secret := "whsec_" + base64.StdEncoding.EncodeToString(secretBytes)
	const subscriptionID = "sub_0123456789abcdef"
	const webhookID = "evt_0123456789abcdef"
	const event = `{"data":{},"eventId":"event-restart","name":"order.created","timestamp":"2026-11-24T00:00:00Z"}`
	statePath := filepath.Join(dir, "events.jsonl")
	cfg := config{Version: 1, Listen: listen, TLSCertFile: certPath, TLSKeyFile: keyPath, CallbackPath: "/hooks", StateFile: statePath, Subscriptions: []subscription{{ID: subscriptionID, Secret: secret}}}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "receiver.json")
	if err := storage.Exclusive(configPath, cfgBytes); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(cert)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	body := []byte(event)
	timestamp := fmt.Sprint(time.Now().Unix())
	signingInput := append([]byte(webhookID+"."+timestamp+"."), body...)
	mac := hmac.New(sha256.New, secretBytes)
	_, _ = mac.Write(signingInput)
	signature := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	send := func() (int, string) {
		request, er := http.NewRequest(http.MethodPost, "https://"+listen+"/hooks", bytes.NewReader(body))
		if er != nil {
			t.Fatal(er)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Webhook-Id", webhookID)
		request.Header.Set("Webhook-Timestamp", timestamp)
		request.Header.Set("Webhook-Signature", signature)
		request.Header.Set("X-MCP-Subscription-Id", subscriptionID)
		response, er := client.Do(request)
		if er != nil {
			t.Fatal(er)
		}
		defer response.Body.Close()
		responseBody, er := io.ReadAll(response.Body)
		if er != nil {
			t.Fatal(er)
		}
		return response.StatusCode, string(responseBody)
	}
	start := func() (*exec.Cmd, io.WriteCloser, *bytes.Buffer, <-chan struct{}) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEventsReceiveTLSSubprocessHelper$")
		cmd.Env = append(os.Environ(), processHelperEnv+"=tls", "MCP_JACK_EVENTS_RECEIVER_CONFIG="+configPath)
		stdin, er := cmd.StdinPipe()
		if er != nil {
			t.Fatal(er)
		}
		stdout, er := cmd.StdoutPipe()
		if er != nil {
			t.Fatal(er)
		}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if er := cmd.Start(); er != nil {
			t.Fatal(er)
		}
		output := new(bytes.Buffer)
		outputDone := make(chan struct{})
		go func() { defer close(outputDone); _, _ = io.Copy(output, stdout) }()
		_ = stderr
		return cmd, stdin, output, outputDone
	}
	awaitReady := func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			response, er := client.Get("https://" + listen + "/missing")
			if er == nil {
				_ = response.Body.Close()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("TLS receiver did not become available")
	}
	cmd, stdin, output, outputDone := start()
	awaitReady()
	if status, ack := send(); status != http.StatusOK || ack != `{"status":"accepted"}` {
		t.Fatalf("first delivery = %d %s", status, ack)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("first receiver: %v", err)
	}
	<-outputDone
	wantOutput := fmt.Sprintf("{\"subscription_id\":%q,\"event\":%s}\n", subscriptionID, event)
	if output.String() != wantOutput {
		t.Fatalf("first output = %q, want %q", output.String(), wantOutput)
	}
	cmd, stdin, output, outputDone = start()
	awaitReady()
	if status, ack := send(); status != http.StatusOK || ack != `{"status":"duplicate"}` {
		t.Fatalf("repeated delivery = %d %s, want duplicate", status, ack)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("restarted receiver: %v", err)
	}
	<-outputDone
	if output.Len() != 0 {
		t.Fatalf("restart emitted second event: %q", output.String())
	}
}

func TestEventsReceiveSubprocessUsesTLSByDefault(t *testing.T) {
	dir := eventsPrivateDir(t)
	certPEM, keyPEM, err := processTLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "receiver.crt"), filepath.Join(dir, "receiver.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	listenSocket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := listenSocket.Addr().String()
	if err := listenSocket.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		Version: 1, Listen: listen, TLSCertFile: certPath, TLSKeyFile: keyPath,
		CallbackPath: "/hooks", StateFile: filepath.Join(dir, "events.jsonl"),
		Subscriptions: []subscription{{ID: "sub_0123456789abcdef", Secret: "whsec_" + base64.StdEncoding.EncodeToString(secretBytes)}},
	}
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "receiver.json")
	if err := storage.Exclusive(configPath, cfgBytes); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestEventsReceiveTLSSubprocessHelper$")
	cmd.Env = append(os.Environ(), processHelperEnv+"=tls", "MCP_JACK_EVENTS_RECEIVER_CONFIG="+configPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: func() *x509.CertPool {
		pool := x509.NewCertPool()
		cert, err := x509.ParseCertificate(func() []byte { block, _ := pem.Decode(certPEM); return block.Bytes }())
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(cert)
		return pool
	}()}}}
	var response *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err = client.Get("https://" + listen + "/missing")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS receiver did not become available: %v; stderr: %s", err, stderr.String())
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("TLS unknown route status=%d, want 404", response.StatusCode)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("TLS receiver subprocess failed: %v; stderr: %s", err, stderr.String())
	}
}

func eventsPrivateDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("private storage is unsupported on this platform")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func processTLSCertificate() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func TestEventsReceiveSubprocessHelper(t *testing.T) {
	if os.Getenv(processHelperEnv) != "1" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()
	if err := Run(ctx, []string{"--config", os.Getenv("MCP_JACK_EVENTS_RECEIVER_CONFIG"), "--loopback-http-test"}, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "eventsreceiver.Run: %v\n", err)
		os.Exit(1)
	}
	// Exit before the test binary prints its PASS line into the checked stdout.
	os.Exit(0)
}

func TestEventsReceiveTLSSubprocessHelper(t *testing.T) {
	if os.Getenv(processHelperEnv) != "tls" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()
	if err := Run(ctx, []string{"--config", os.Getenv("MCP_JACK_EVENTS_RECEIVER_CONFIG")}, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "TLS eventsreceiver.Run: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
