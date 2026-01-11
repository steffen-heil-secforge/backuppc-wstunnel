package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	backuppcConfDir string
	certDir         string
	listenAddr      string
	localListenAddr string
	defaultPort     int
	upgrader        = websocket.Upgrader{
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
	}
	activeMu sync.Mutex
	active   = make(map[string]context)

	// Regex to parse Perl config: $Conf{RsyncdClientPort} = 64701;
	portRegex = regexp.MustCompile(`\$Conf\{RsyncdClientPort\}\s*=\s*['"]?(\d+)['"]?\s*;`)
	// Regex to parse fingerprint from $Conf{ClientComment}: TunnelCert:sha256:abc123...
	commentRegex      = regexp.MustCompile(`\$Conf\{ClientComment\}\s*=\s*['"](.+?)['"]\s*;`)
	fingerprintInText = regexp.MustCompile(`TunnelCert:(sha256:[a-fA-F0-9]+)`)
)

type context struct {
	cancel chan struct{}
	done   chan struct{} // signaled by DumpPostUserCmd via /done endpoint
}

func main() {
	flag.StringVar(&backuppcConfDir, "backuppc-conf", "/etc/backuppc", "BackupPC configuration directory")
	flag.StringVar(&certDir, "certs", "/etc/backuppc-tunnel", "Certificate directory")
	flag.StringVar(&listenAddr, "listen", ":8443", "Listen address for tunnel (mTLS)")
	flag.StringVar(&localListenAddr, "local-listen", "127.0.0.1:8444", "Listen address for local API (done signal)")
	flag.IntVar(&defaultPort, "default-port", 64700, "Default port if not configured in BackupPC")
	flag.Parse()

	// Load CA for client verification
	caCert, err := os.ReadFile(certDir + "/ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA cert")
	}

	// TLS config with mandatory client certs for /tunnel
	tlsConfig := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	// Main server for tunnel connections (mTLS)
	tunnelServer := &http.Server{
		Addr:         listenAddr,
		TLSConfig:    tlsConfig,
		Handler:      http.HandlerFunc(handleTunnel),
		ReadTimeout:  0, // No timeout for long-running tunnels
		WriteTimeout: 0,
	}

	// Local server for done signal (localhost only, no TLS)
	localMux := http.NewServeMux()
	localMux.HandleFunc("/done/", handleDone) // /done/<hostname>
	localServer := &http.Server{
		Addr:    localListenAddr,
		Handler: localMux,
	}

	log.Printf("backuppc-tunnel server starting on %s (tunnel) and %s (local API)", listenAddr, localListenAddr)
	log.Printf("Reading BackupPC config from %s", backuppcConfDir)

	// Start local server in background
	go func() {
		if err := localServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Local server failed: %v", err)
		}
	}()

	// Start main TLS server
	err = tunnelServer.ListenAndServeTLS(
		certDir+"/server.crt",
		certDir+"/server.key",
	)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// handleDone is called by BackupPC's DumpPostUserCmd to signal backup completion
func handleDone(w http.ResponseWriter, r *http.Request) {
	// Extract hostname from path: /done/<hostname>
	hostname := strings.TrimPrefix(r.URL.Path, "/done/")
	if hostname == "" {
		http.Error(w, "Missing hostname", http.StatusBadRequest)
		return
	}

	activeMu.Lock()
	ctx, exists := active[hostname]
	activeMu.Unlock()

	if !exists {
		log.Printf("Done signal for '%s' but no active tunnel", hostname)
		http.Error(w, "No active tunnel for host", http.StatusNotFound)
		return
	}

	// Signal the tunnel that backup is complete
	select {
	case <-ctx.done:
		// Already signaled
	default:
		close(ctx.done)
	}

	log.Printf("Received done signal for '%s'", hostname)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}

// getClientPort reads the RsyncdClientPort from BackupPC config for a host
func getClientPort(hostname string) (int, error) {
	// First try host-specific config
	hostConf := fmt.Sprintf("%s/%s.pl", backuppcConfDir, hostname)
	if port, err := parsePortFromFile(hostConf); err == nil {
		return port, nil
	}

	// Fall back to main config
	mainConf := fmt.Sprintf("%s/config.pl", backuppcConfDir)
	if port, err := parsePortFromFile(mainConf); err == nil {
		return port, nil
	}

	// Use default
	return defaultPort, nil
}

func parsePortFromFile(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := portRegex.FindStringSubmatch(line)
		if len(matches) == 2 {
			port, err := strconv.Atoi(matches[1])
			if err == nil && port > 0 && port < 65536 {
				return port, nil
			}
		}
	}
	return 0, fmt.Errorf("port not found in %s", filename)
}

// getCertFingerprint reads the expected fingerprint from ClientComment in BackupPC config
func getCertFingerprint(hostname string) (string, error) {
	hostConf := fmt.Sprintf("%s/%s.pl", backuppcConfDir, hostname)
	return parseFingerprintFromFile(hostConf)
}

func parseFingerprintFromFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for ClientComment containing TunnelCert:sha256:...
		commentMatch := commentRegex.FindStringSubmatch(line)
		if len(commentMatch) == 2 {
			fpMatch := fingerprintInText.FindStringSubmatch(commentMatch[1])
			if len(fpMatch) == 2 {
				return strings.ToLower(fpMatch[1]), nil
			}
		}
	}
	return "", fmt.Errorf("fingerprint not found in %s (add TunnelCert:sha256:... to ClientComment)", filename)
}

// calculateCertFingerprint returns the SHA256 fingerprint of a certificate
func calculateCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// checkHostExists verifies the host is configured in BackupPC
func checkHostExists(hostname string) bool {
	hostsFile := fmt.Sprintf("%s/hosts", backuppcConfDir)
	file, err := os.Open(hostsFile)
	if err != nil {
		log.Printf("Warning: cannot read hosts file: %v", err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		// hosts file format: hostname\tdhcp\tuser\tmoreUsers
		var host string
		fmt.Sscanf(line, "%s", &host)
		if host == hostname {
			return true
		}
	}
	return false
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	// Extract CN from verified client cert
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		log.Printf("Connection without client certificate from %s", r.RemoteAddr)
		http.Error(w, "No client certificate", http.StatusForbidden)
		return
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName

	// Check if host exists in BackupPC
	if !checkHostExists(cn) {
		log.Printf("Host '%s' not found in BackupPC hosts file (from %s)", cn, r.RemoteAddr)
		http.Error(w, "Unknown host", http.StatusForbidden)
		return
	}

	// Validate certificate fingerprint
	certFingerprint := calculateCertFingerprint(r.TLS.PeerCertificates[0])
	expectedFingerprint, err := getCertFingerprint(cn)
	if err != nil {
		log.Printf("No fingerprint configured for '%s', rejecting (from %s)", cn, r.RemoteAddr)
		http.Error(w, "Certificate not registered", http.StatusForbidden)
		return
	}
	if certFingerprint != expectedFingerprint {
		log.Printf("Certificate fingerprint mismatch for '%s': got %s, expected %s (from %s)",
			cn, certFingerprint, expectedFingerprint, r.RemoteAddr)
		http.Error(w, "Certificate fingerprint mismatch", http.StatusForbidden)
		return
	}

	// Get port from BackupPC config
	port, err := getClientPort(cn)
	if err != nil {
		log.Printf("Failed to get port for '%s': %v", cn, err)
		http.Error(w, "Configuration error", http.StatusInternalServerError)
		return
	}

	// Check if already connected
	activeMu.Lock()
	if ctx, exists := active[cn]; exists {
		activeMu.Unlock()
		log.Printf("Client '%s' already connected, rejecting new connection", cn)
		_ = ctx
		http.Error(w, "Already connected", http.StatusConflict)
		return
	}
	ctx := context{
		cancel: make(chan struct{}),
		done:   make(chan struct{}),
	}
	active[cn] = ctx
	activeMu.Unlock()

	defer func() {
		activeMu.Lock()
		delete(active, cn)
		activeMu.Unlock()
		log.Printf("Client '%s' disconnected", cn)
	}()

	// Create local listener for BackupPC
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Printf("Failed to bind port %d for '%s': %v", port, cn, err)
		http.Error(w, "Port unavailable", http.StatusInternalServerError)
		return
	}
	defer listener.Close()

	// Upgrade to WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for '%s': %v", cn, err)
		return
	}
	defer ws.Close()

	log.Printf("Client '%s' connected from %s (tunnel port %d)", cn, r.RemoteAddr, port)

	// Trigger backup in background
	go triggerBackup(cn)

	// Channels for coordination
	wsData := make(chan []byte, 10)
	wsError := make(chan error, 1)
	tunnelDone := make(chan struct{})

	// Single WebSocket reader goroutine - runs for entire tunnel lifetime
	go func() {
		defer close(wsData)
		for {
			select {
			case <-tunnelDone:
				return
			default:
			}
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				select {
				case wsError <- err:
				default:
				}
				return
			}
			if msgType == websocket.CloseMessage {
				select {
				case wsError <- nil:
				default:
				}
				return
			}
			if msgType == websocket.BinaryMessage {
				select {
				case wsData <- data:
				case <-tunnelDone:
					return
				}
			}
		}
	}()

	defer close(tunnelDone)

	// Accept BackupPC connections until done signal or idle timeout
	idleTimeout := 30 * time.Second
	lastActivity := time.Now()
	connectionCount := 0
	doneReceived := false

	for {
		select {
		case <-ctx.cancel:
			log.Printf("Tunnel cancelled for '%s'", cn)
			return
		case <-ctx.done:
			doneReceived = true
			log.Printf("Done signal received for '%s' after %d connections", cn, connectionCount)
			goto finished
		case err := <-wsError:
			if err != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("WebSocket error for '%s': %v", cn, err)
			}
			log.Printf("WebSocket closed for '%s'", cn)
			return
		default:
		}

		// Check idle timeout (only after at least one connection was handled)
		if connectionCount > 0 && time.Since(lastActivity) > idleTimeout {
			log.Printf("WARNING: Idle timeout for '%s' after %d connections (no done signal received!)", cn, connectionCount)
			break
		}

		// Accept BackupPC TCP connection
		deadline := time.Second
		if connectionCount == 0 && time.Since(lastActivity) < 2*time.Minute {
			// Still waiting for first connection
		} else if connectionCount == 0 {
			log.Printf("Timeout waiting for BackupPC to connect for '%s'", cn)
			ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "timeout"))
			return
		}

		listener.(*net.TCPListener).SetDeadline(time.Now().Add(deadline))
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
					log.Printf("Client '%s' disconnected while waiting: %v", cn, err)
					return
				}
				continue
			}
			log.Printf("Accept error for '%s': %v", cn, err)
			return
		}

		// Handle this BackupPC connection
		connectionCount++
		log.Printf("BackupPC connection #%d for '%s'", connectionCount, cn)
		ok := handleBackupPCConnectionWithChannel(ws, conn, cn, wsData, wsError)
		lastActivity = time.Now()
		log.Printf("BackupPC connection #%d completed for '%s'", connectionCount, cn)
		if !ok {
			log.Printf("Error during connection #%d for '%s', stopping tunnel", connectionCount, cn)
			return
		}
	}

finished:
	if doneReceived {
		log.Printf("Backup completed for '%s' (%d shares), closing tunnel", cn, connectionCount)
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "backup complete"))
	} else {
		log.Printf("ERROR: Backup for '%s' ended by idle timeout without done signal - DumpPostUserCmd may not be configured!", cn)
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, "idle timeout without done signal"))
	}
}

// handleBackupPCConnectionWithChannel handles a single BackupPC TCP connection
// using data from the shared WebSocket reader channel.
// Returns true if connection completed normally (TCP closed),
// false if WebSocket error occurred (should stop accepting new connections)
func handleBackupPCConnectionWithChannel(ws *websocket.Conn, tcp net.Conn, cn string, wsData <-chan []byte, wsError <-chan error) (ok bool) {
	defer tcp.Close()

	tcpDone := make(chan struct{})

	// TCP -> WebSocket (BackupPC sending data to client)
	go func() {
		defer close(tcpDone)
		buf := make([]byte, 32*1024)
		for {
			n, err := tcp.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("TCP read error for '%s': %v", cn, err)
				}
				return
			}
			ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				log.Printf("WebSocket write error for '%s': %v", cn, err)
				return
			}
		}
	}()

	// WebSocket -> TCP: receive from channel and forward to TCP
	for {
		select {
		case <-tcpDone:
			// TCP closed - BackupPC finished this share
			if tcpConn, ok := tcp.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}
			log.Printf("BackupPC connection closed for '%s'", cn)
			return true

		case data, ok := <-wsData:
			if !ok {
				// Channel closed - WebSocket reader exited
				log.Printf("WebSocket channel closed for '%s'", cn)
				return false
			}
			tcp.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := tcp.Write(data); err != nil {
				log.Printf("TCP write error for '%s': %v", cn, err)
				return true // TCP error, but WebSocket is fine - can continue with next connection
			}

		case err := <-wsError:
			// WebSocket error from reader goroutine
			if err != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("WebSocket error for '%s': %v", cn, err)
			}
			return false
		}
	}
}

func triggerBackup(hostname string) {
	// Small delay to ensure tunnel is fully established
	time.Sleep(500 * time.Millisecond)

	log.Printf("Triggering backup for '%s'", hostname)
	cmd := exec.Command(
		"sudo", "-u", "backuppc",
		"/usr/share/backuppc/bin/BackupPC_serverMesg",
		"backup", hostname, hostname, "backuppc", "1",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to trigger backup for '%s': %v\nOutput: %s", hostname, err, output)
	} else {
		log.Printf("Backup triggered for '%s': %s", hostname, output)
	}
}
