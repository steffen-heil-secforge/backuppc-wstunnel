package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var (
	bytesReceived uint64 // from server (BackupPC -> client)
	bytesSent     uint64 // to server (client -> BackupPC)
	rsyncProcess  *os.Process
	rsyncMu       sync.Mutex
	wsMu          sync.Mutex // protects WebSocket writes
	outputMu      sync.Mutex // protects console output
	progressShown bool       // true if progress line is currently displayed
)

var (
	serverAddr  string
	certFile    string
	keyFile     string
	caFile      string
	configFile  string
	rsyncConfig string
	timeout     time.Duration
)

func main() {
	// Initialize process group handling (Job Objects on Windows)
	if err := initProcessGroup(); err != nil {
		log.Printf("Warning: failed to initialize process group: %v", err)
	}

	flag.StringVar(&configFile, "config", "", "Config file containing server, certs, and key (alternative to individual flags)")
	flag.StringVar(&serverAddr, "server", "", "Server address (e.g., backup.example.com:443)")
	flag.StringVar(&certFile, "cert", "", "Client certificate file")
	flag.StringVar(&keyFile, "key", "", "Client key file")
	flag.StringVar(&caFile, "ca", "", "CA certificate file (optional, uses system roots if not set)")
	flag.StringVar(&rsyncConfig, "rsync-config", "rsyncd.conf", "Path to rsyncd.conf for module definitions")
	flag.DurationVar(&timeout, "timeout", 4*time.Hour, "Maximum backup duration")
	flag.Parse()

	// Load from config file if specified
	var clientCertPEM, clientKeyPEM, caCertPEM []byte
	if configFile != "" {
		var err error
		serverAddr, clientCertPEM, clientKeyPEM, caCertPEM, err = parseConfigFile(configFile)
		if err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
	}

	if serverAddr == "" || (configFile == "" && (certFile == "" || keyFile == "")) {
		fmt.Fprintln(os.Stderr, "Usage: backuppc-tunnel-client -config FILE [-rsync-config FILE] [-timeout DURATION]")
		fmt.Fprintln(os.Stderr, "   or: backuppc-tunnel-client -server HOST:PORT -cert FILE -key FILE [-ca FILE] [-rsync-config FILE] [-timeout DURATION]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load client certificate
	var cert tls.Certificate
	var err error
	if configFile != "" {
		cert, err = tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	} else {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	}
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}

	// Setup TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Load CA certificate
	if configFile != "" && len(caCertPEM) > 0 {
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCertPEM) {
			log.Fatal("Failed to parse CA certificate from config")
		}
		tlsConfig.RootCAs = caPool
	} else if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("Failed to read CA certificate: %v", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			log.Fatal("Failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Connect to server
	u := url.URL{Scheme: "wss", Host: serverAddr, Path: "/tunnel"}
	log.Printf("Connecting to %s", u.String())

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	ws, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		if resp != nil {
			log.Fatalf("Connection failed: %v (HTTP %d)", err, resp.StatusCode)
		}
		log.Fatalf("Connection failed: %v", err)
	}
	defer ws.Close()

	log.Println("Connected to server, backup will start automatically")

	// Start progress display
	stopProgress := make(chan struct{})
	go displayProgress(stopProgress)

	// Setup ping/pong for keepalive
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(timeout))
		return nil
	})

	// Handle incoming data from server (BackupPC -> rsync)
	done := make(chan error, 1)
	go func() {
		done <- handleConnection(ws)
	}()

	// Wait for completion or signal
	select {
	case err := <-done:
		close(stopProgress)
		if err != nil {
			log.Printf("Backup failed: %v", err)
			os.Exit(1)
		}
		log.Printf("Backup completed successfully (sent %s, received %s)",
			formatBytes(atomic.LoadUint64(&bytesSent)),
			formatBytes(atomic.LoadUint64(&bytesReceived)))
	case sig := <-sigChan:
		close(stopProgress)
		log.Printf("Received signal %v, disconnecting", sig)
		killRsync()
		wsMu.Lock()
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		wsMu.Unlock()
		os.Exit(0)
	case <-time.After(timeout):
		close(stopProgress)
		log.Printf("Timeout after %v", timeout)
		killRsync()
		os.Exit(1)
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func displayProgress(stop chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	for {
		select {
		case <-stop:
			// Clear progress line on exit
			outputMu.Lock()
			if progressShown {
				fmt.Printf("\r%80s\r", "")
				progressShown = false
			}
			outputMu.Unlock()
			return
		case <-ticker.C:
			sent := atomic.LoadUint64(&bytesSent)
			recv := atomic.LoadUint64(&bytesReceived)
			elapsed := time.Since(start).Round(time.Second)
			outputMu.Lock()
			fmt.Printf("\r[%s] Sent: %s | Received: %s    ", elapsed, formatBytes(sent), formatBytes(recv))
			progressShown = true
			outputMu.Unlock()
		}
	}
}

// logMsg logs a message, clearing the progress line first if needed
func logMsg(format string, v ...interface{}) {
	outputMu.Lock()
	if progressShown {
		fmt.Printf("\r%80s\r", "") // clear progress line
		progressShown = false
	}
	outputMu.Unlock()
	log.Printf(format, v...)
}

func killRsync() {
	rsyncMu.Lock()
	defer rsyncMu.Unlock()
	killProcessGroup()
	if rsyncProcess != nil {
		rsyncProcess.Kill()
		rsyncProcess.Wait()
		rsyncProcess = nil
	}
}

// windowsToCygwinPath converts a Windows path to Cygwin format
// e.g., "Z:\foo\bar" -> "/cygdrive/z/foo/bar"
func windowsToCygwinPath(winPath string) string {
	if len(winPath) >= 2 && winPath[1] == ':' {
		drive := strings.ToLower(string(winPath[0]))
		rest := strings.ReplaceAll(winPath[2:], "\\", "/")
		return "/cygdrive/" + drive + rest
	}
	return strings.ReplaceAll(winPath, "\\", "/")
}

func handleConnection(ws *websocket.Conn) error {
	var rsyncCmd *exec.Cmd
	var rsyncStdin io.WriteCloser
	var rsyncStarted bool
	var rsyncDone chan struct{}
	var mu sync.Mutex // protects rsyncStarted and rsyncStdin

	// Cleanup function
	cleanup := func() {
		mu.Lock()
		if rsyncStdin != nil {
			rsyncStdin.Close()
		}
		mu.Unlock()
		killRsync()
	}
	defer cleanup()

	for {
		ws.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msgType, data, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil // Normal close
			}
			// "close sent" means we initiated close
			if strings.Contains(err.Error(), "close sent") {
				return nil
			}
			return fmt.Errorf("websocket read error: %v", err)
		}

		switch msgType {
		case websocket.BinaryMessage:
			// Data from BackupPC, forward to rsync
			atomic.AddUint64(&bytesReceived, uint64(len(data)))

			// Loop to handle rsync restart between modules
			for attempt := 0; attempt < 3; attempt++ {
				mu.Lock()
				needStart := !rsyncStarted
				mu.Unlock()

				if needStart {
					// Find rsync binary and config
					rsyncBinary := "rsync"
					configPath := rsyncConfig
					if runtime.GOOS == "windows" {
						exePath, err := os.Executable()
						if err == nil {
							exeDir := filepath.Dir(exePath)
							rsyncBinary = filepath.Join(exeDir, "rsync.exe")
							// Make config path absolute if relative
							if !filepath.IsAbs(rsyncConfig) {
								configPath = filepath.Join(exeDir, rsyncConfig)
							}
							// Convert to Cygwin path format to avoid warning
							configPath = windowsToCygwinPath(configPath)
						}
					}

					// Start rsync in server mode with daemon config (stdin/stdout)
					rsyncCmd = exec.Command(rsyncBinary, "--server", "--daemon", "--config", configPath, ".")
					rsyncCmd.Dir = filepath.Dir(rsyncBinary) // Set working dir so rsync finds its DLLs
					rsyncCmd.Env = append(os.Environ(), "PATH="+filepath.Dir(rsyncBinary)+";"+os.Getenv("PATH"))
					rsyncCmd.Stderr = os.Stderr
					setupProcessGroup(rsyncCmd)

					rsyncStdin, err = rsyncCmd.StdinPipe()
					if err != nil {
						return fmt.Errorf("failed to get rsync stdin: %v", err)
					}

					rsyncStdout, err := rsyncCmd.StdoutPipe()
					if err != nil {
						return fmt.Errorf("failed to get rsync stdout: %v", err)
					}

					if err := rsyncCmd.Start(); err != nil {
						return fmt.Errorf("failed to start rsync: %v", err)
					}
					if err := assignToProcessGroup(rsyncCmd); err != nil {
						logMsg("Warning: failed to assign rsync to process group: %v", err)
					}
					rsyncMu.Lock()
					rsyncProcess = rsyncCmd.Process
					rsyncMu.Unlock()
					logMsg("Started rsync")

					mu.Lock()
					rsyncStarted = true
					rsyncDone = make(chan struct{})
					currentDone := rsyncDone
					currentStdin := rsyncStdin
					mu.Unlock()

					// Read from rsync stdout and send to WebSocket
					go func() {
						buf := make([]byte, 32*1024)
						for {
							n, err := rsyncStdout.Read(buf)
							if err != nil {
								if err != io.EOF {
									logMsg("rsync read error: %v", err)
								}
								// rsync finished this module - reset for next module
								logMsg("rsync module completed, ready for next")
								mu.Lock()
								if currentStdin != nil {
									currentStdin.Close()
								}
								rsyncStarted = false
								rsyncStdin = nil
								mu.Unlock()
								close(currentDone)
								return
							}
							atomic.AddUint64(&bytesSent, uint64(n))
							wsMu.Lock()
							ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
							err = ws.WriteMessage(websocket.BinaryMessage, buf[:n])
							wsMu.Unlock()
							if err != nil {
								logMsg("websocket write error: %v", err)
								return
							}
						}
					}()
				}

				// Forward data to rsync stdin
				mu.Lock()
				stdin := rsyncStdin
				mu.Unlock()
				if stdin != nil {
					if _, err := stdin.Write(data); err != nil {
						// rsync might have exited, wait briefly for it to reset and retry
						time.Sleep(100 * time.Millisecond)
						continue // retry with new rsync
					}
					break // success
				} else {
					// No stdin yet, wait and retry
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

		case websocket.CloseMessage:
			return nil

		case websocket.PingMessage:
			wsMu.Lock()
			ws.WriteMessage(websocket.PongMessage, data)
			wsMu.Unlock()
		}
	}
}

// parseConfigFile reads a bundled config file containing server address and PEM data
// Format:
//
//	server = hostname:port
//	-----BEGIN CERTIFICATE-----
//	(client cert)
//	-----END CERTIFICATE-----
//	-----BEGIN PRIVATE KEY----- (or RSA PRIVATE KEY)
//	(client key)
//	-----END PRIVATE KEY-----
//	-----BEGIN CERTIFICATE-----
//	(CA cert)
//	-----END CERTIFICATE-----
func parseConfigFile(filename string) (server string, clientCert, clientKey, caCert []byte, err error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("cannot read config file: %v", err)
	}

	// Parse server address from first non-empty, non-comment line or "server = " line
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-----BEGIN") {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "server") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				server = strings.TrimSpace(parts[1])
			}
		} else if server == "" {
			// First non-comment line without "server=" is treated as server address
			server = line
		}
	}

	if server == "" {
		return "", nil, nil, nil, fmt.Errorf("no server address found in config file")
	}

	// Parse PEM blocks
	var certs [][]byte
	var key []byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		pemData := pem.EncodeToMemory(block)
		switch block.Type {
		case "CERTIFICATE":
			certs = append(certs, pemData)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			key = pemData
		}
	}

	if len(certs) < 1 {
		return "", nil, nil, nil, fmt.Errorf("no certificates found in config file")
	}
	if key == nil {
		return "", nil, nil, nil, fmt.Errorf("no private key found in config file")
	}

	clientCert = certs[0]
	clientKey = key
	if len(certs) > 1 {
		caCert = certs[1]
	}

	return server, clientCert, clientKey, caCert, nil
}
