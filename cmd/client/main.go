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
	statusLine    string     // current status line content
	statusShown   bool       // true if status line is currently displayed
)

// updateStatus updates the current status line in-place
func updateStatus(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	line := fmt.Sprintf("%s %s", timestamp, msg)

	outputMu.Lock()
	defer outputMu.Unlock()

	// Clear current line and print new status
	fmt.Printf("\r%-80s\r%s", "", line)
	statusLine = line
	statusShown = true
}

// finalizeStatus prints the current status as final (with newline) and clears state
func finalizeStatus() {
	outputMu.Lock()
	defer outputMu.Unlock()

	if statusShown {
		fmt.Println() // Move to next line
		statusShown = false
		statusLine = ""
	}
}

// printLine prints a complete line (finalizes any status first)
func printLine(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006/01/02 15:04:05")

	outputMu.Lock()
	defer outputMu.Unlock()

	if statusShown {
		fmt.Printf("\r%-80s\r", "") // Clear status line
		statusShown = false
		statusLine = ""
	}
	fmt.Printf("%s %s\n", timestamp, msg)
}

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
	updateStatus("Connecting to %s...", u.String())

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 30 * time.Second,
	}

	ws, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		finalizeStatus()
		if resp != nil {
			log.Fatalf("Connection failed: %v (HTTP %d)", err, resp.StatusCode)
		}
		log.Fatalf("Connection failed: %v", err)
	}
	defer ws.Close()

	updateStatus("Connected to %s", u.String())
	finalizeStatus()

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
			finalizeStatus()
			printLine("Backup failed: %v", err)
			os.Exit(1)
		}
		// Replace progress line with final message
		updateStatus("Done")
		finalizeStatus()
	case sig := <-sigChan:
		close(stopProgress)
		finalizeStatus()
		printLine("Received signal %v, disconnecting", sig)
		killRsync()
		wsMu.Lock()
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		wsMu.Unlock()
		os.Exit(0)
	case <-time.After(timeout):
		close(stopProgress)
		finalizeStatus()
		printLine("Timeout after %v", timeout)
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
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			sent := atomic.LoadUint64(&bytesSent)
			recv := atomic.LoadUint64(&bytesReceived)
			elapsed := time.Since(start).Round(time.Second)
			updateStatus("[%s] Total - Sent: %s | Received: %s", elapsed, formatBytes(sent), formatBytes(recv))
		}
	}
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

// Protocol constants
// Data messages: [connID 0-254][data...]
// Close messages: [255][connID] (2 bytes total)
const connIDCloseMarker = 255

// rsyncConnection tracks state for a single rsync connection
type rsyncConnection struct {
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	connID       byte
	moduleName   string
	parseState   int // 0=waiting for version, 1=waiting for module, 2=done
	parseBuf     []byte
	bytesRecv    uint64 // bytes received for this connection
	bytesSent    uint64 // bytes sent for this connection
	startTime    time.Time
}

// parseModuleName extracts the module name from rsync protocol data
// Returns the module name if found, empty string otherwise
func (c *rsyncConnection) parseModuleName(data []byte) {
	if c.parseState == 2 {
		return // Already parsed
	}

	c.parseBuf = append(c.parseBuf, data...)

	for {
		// Find newline
		idx := bytes.IndexByte(c.parseBuf, '\n')
		if idx == -1 {
			// Limit buffer size to prevent memory issues
			if len(c.parseBuf) > 1024 {
				c.parseState = 2 // Give up
			}
			return
		}

		line := string(c.parseBuf[:idx])
		c.parseBuf = c.parseBuf[idx+1:]

		switch c.parseState {
		case 0: // Waiting for version line
			if strings.HasPrefix(line, "@RSYNCD:") {
				c.parseState = 1
			}
		case 1: // Waiting for module name
			// Module name is the next non-empty line after version
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "@") {
				c.moduleName = line
				c.parseState = 2
				// Print module name as permanent line, progress will appear below
				printLine("Backing up %s (#%d)...", c.moduleName, c.connID)
				return
			}
		}
	}
}

func handleConnection(ws *websocket.Conn) error {
	var currentConn *rsyncConnection
	var mu sync.Mutex // protects currentConn

	// Cleanup function
	cleanup := func() {
		mu.Lock()
		if currentConn != nil && currentConn.stdin != nil {
			currentConn.stdin.Close()
		}
		mu.Unlock()
		killRsync()
	}
	defer cleanup()

	// startRsync starts a new rsync process for the given connection ID
	startRsync := func(connID byte) (*rsyncConnection, error) {
		// Find rsync binary and config
		rsyncBinary := "rsync"
		configPath := rsyncConfig
		if runtime.GOOS == "windows" {
			exePath, err := os.Executable()
			if err == nil {
				exeDir := filepath.Dir(exePath)
				rsyncBinary = filepath.Join(exeDir, "rsync.exe")
				if !filepath.IsAbs(rsyncConfig) {
					configPath = filepath.Join(exeDir, rsyncConfig)
				}
				configPath = windowsToCygwinPath(configPath)
			}
		}

		cmd := exec.Command(rsyncBinary, "--server", "--daemon", "--config", configPath, ".")
		cmd.Dir = filepath.Dir(rsyncBinary)
		cmd.Env = append(os.Environ(), "PATH="+filepath.Dir(rsyncBinary)+";"+os.Getenv("PATH"))
		cmd.Stderr = os.Stderr
		setupProcessGroup(cmd)

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to get rsync stdin: %v", err)
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to get rsync stdout: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start rsync: %v", err)
		}
		if err := assignToProcessGroup(cmd); err != nil {
			printLine("Warning: failed to assign rsync to process group: %v", err)
		}
		rsyncMu.Lock()
		rsyncProcess = cmd.Process
		rsyncMu.Unlock()
		updateStatus("Starting backup (#%d)...", connID)

		conn := &rsyncConnection{
			cmd:       cmd,
			stdin:     stdin,
			connID:    connID,
			startTime: time.Now(),
		}

		// Read from rsync stdout and send to WebSocket with connection ID prefix
		go func(c *rsyncConnection) {
			buf := make([]byte, 32*1024)
			for {
				n, err := stdout.Read(buf)
				if err != nil {
					if err != io.EOF {
						printLine("rsync read error: %v", err)
					}
					// Log module completion with stats
					elapsed := time.Since(c.startTime).Round(time.Second)
					moduleName := c.moduleName
					if moduleName == "" {
						moduleName = fmt.Sprintf("module #%d", c.connID)
					}
					printLine("Backup of %s complete: sent %s, received %s, duration %s",
						moduleName, formatBytes(c.bytesSent), formatBytes(c.bytesRecv), elapsed)
					// Send close signal: [255][connID]
					wsMu.Lock()
					ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
					ws.WriteMessage(websocket.BinaryMessage, []byte{connIDCloseMarker, connID})
					wsMu.Unlock()
					// Clean up
					mu.Lock()
					if currentConn != nil && currentConn.connID == connID {
						if currentConn.stdin != nil {
							currentConn.stdin.Close()
						}
						currentConn = nil
					}
					mu.Unlock()
					return
				}
				atomic.AddUint64(&bytesSent, uint64(n))
				c.bytesSent += uint64(n)
				// Send with connection ID prefix: [connID][data...]
				msg := make([]byte, n+1)
				msg[0] = connID
				copy(msg[1:], buf[:n])
				wsMu.Lock()
				ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
				err = ws.WriteMessage(websocket.BinaryMessage, msg)
				wsMu.Unlock()
				if err != nil {
					printLine("websocket write error: %v", err)
					return
				}
			}
		}(conn)

		return conn, nil
	}

	for {
		ws.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msgType, data, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			if strings.Contains(err.Error(), "close sent") {
				return nil
			}
			return fmt.Errorf("websocket read error: %v", err)
		}

		switch msgType {
		case websocket.BinaryMessage:
			if len(data) < 1 {
				continue
			}
			atomic.AddUint64(&bytesReceived, uint64(len(data)))

			// Check for close signal: [255][connID]
			if data[0] == connIDCloseMarker {
				if len(data) < 2 {
					continue
				}
				closeConnID := data[1]
				mu.Lock()
				if currentConn != nil && currentConn.connID == closeConnID {
					if currentConn.stdin != nil {
						currentConn.stdin.Close()
					}
					currentConn = nil
				}
				mu.Unlock()
				continue
			}

			// Data message: [connID][data...]
			connID := data[0]
			payload := data[1:]

			mu.Lock()
			// Check if we need to start a new rsync (new connection ID)
			if currentConn == nil || currentConn.connID != connID {
				// Close old connection if exists
				if currentConn != nil && currentConn.stdin != nil {
					currentConn.stdin.Close()
				}
				mu.Unlock()
				// Start new rsync for this connection
				conn, err := startRsync(connID)
				if err != nil {
					return err
				}
				mu.Lock()
				currentConn = conn
			}
			stdin := currentConn.stdin
			mu.Unlock()

			// Track per-connection bytes received
			currentConn.bytesRecv += uint64(len(payload))

			// Parse module name from rsync protocol
			if currentConn.parseState < 2 {
				currentConn.parseModuleName(payload)
			}

			// Forward data to rsync stdin
			if stdin != nil && len(payload) > 0 {
				if _, err := stdin.Write(payload); err != nil {
					printLine("Failed to write to rsync stdin: %v", err)
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
