package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	pb "agent-ui/proto"

	"github.com/hpcloud/tail"
	"golang.org/x/sys/windows/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type LogConfig struct {
	ManagerIP  string   `json:"manager_ip"`
	FilePaths  []string `json:"file_paths"`
	SyslogPort int      `json:"syslog_port"`
	WinEvents  []string `json:"win_events"`
}

// App struct
type App struct {
	ctx        context.Context
	config     LogConfig
	grpcConn   *grpc.ClientConn
	grpcClient pb.EventServiceClient
	cancelFunc context.CancelFunc // Used to stop collectors when config changes
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.LoadConfig()
	if a.config.ManagerIP != "" {
		a.StartCollectors()
	}
}

// LoadConfig loads the settings from agent_config.json
// If the Manager IP is empty, it attempts to read it from the registry set by the MSI installer.
func (a *App) LoadConfig() LogConfig {
	configPath := getConfigPath()
	file, err := os.ReadFile(configPath)
	if err == nil {
		json.Unmarshal(file, &a.config)
	}

	// Fallback to MSI registry key if Manager IP is missing
	if a.config.ManagerIP == "" && runtime.GOOS == "windows" {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\SIEMAgent`, registry.QUERY_VALUE)
		if err == nil {
			defer k.Close()
			ip, _, err := k.GetStringValue("ManagerIP")
			if err == nil && ip != "" {
				a.config.ManagerIP = ip
				a.SaveConfig(a.config) // Persist it to the json config for future use
				log.Printf("Loaded Manager IP from Registry: %s", ip)
			}
		}
	}

	return a.config
}

// SaveConfig saves the UI changes and restarts the log collectors
func (a *App) SaveConfig(config LogConfig) string {
	a.config = config
	data, _ := json.MarshalIndent(config, "", "  ")
	
	configPath := getConfigPath()
	err := os.WriteFile(configPath, data, 0644)
	if err != nil {
		return fmt.Sprintf("Error saving config: %v", err)
	}

	a.StartCollectors() // Restart the engine with new config
	return "Configuration saved successfully!"
}

func getConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "agent_config.json" // fallback
	}
	appDir := configDir + "/SIEMAgent"
	os.MkdirAll(appDir, 0755)
	return appDir + "/agent_config.json"
}

// StartCollectors initiates the gRPC connection and spawns the dynamic log listeners
func (a *App) StartCollectors() {
	if a.cancelFunc != nil {
		a.cancelFunc() // Cancel old goroutines
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.cancelFunc = cancel

	if a.grpcConn != nil {
		a.grpcConn.Close()
	}

	var err error
	addr := a.config.ManagerIP
	if !strings.Contains(addr, ":") {
		addr += ":50051"
	}

	a.grpcConn, err = grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect to manager: %v", err)
		return
	}
	a.grpcClient = pb.NewEventServiceClient(a.grpcConn)

	// Send Heartbeat in a goroutine
	go a.heartbeatRoutine(ctx)

	// Open streaming channel
	stream, err := a.grpcClient.StreamEvents(ctx)
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return
	}

	logChan := make(chan *pb.EventMessage, 100)

	// Start File tailers
	for _, path := range a.config.FilePaths {
		go a.tailFile(ctx, path, logChan)
	}

	// Start ETW listener on Windows instead of PowerShell polling
	if runtime.GOOS == "windows" {
		go StartETW(ctx, logChan)
	}

	// Start Syslog UDP listener if defined
	if a.config.SyslogPort > 0 {
		go a.listenSyslog(ctx, a.config.SyslogPort, logChan)
	}

	// Forwarder loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-logChan:
				if stream != nil {
					stream.Send(event)
				}
			}
		}
	}()
}

func (a *App) heartbeatRoutine(ctx context.Context) {
	hostname, _ := os.Hostname()
	
	colls := []string{}
	colls = append(colls, a.config.FilePaths...)
	colls = append(colls, a.config.WinEvents...)
	activeCollectorsStr, _ := json.Marshal(colls)

	info := &pb.AgentInfo{
		AgentId:          hostname,
		Os:               runtime.GOOS,
		IpAddress:        getLocalIP(),
		Hostname:         hostname,
		Version:          "v2.0-GUI",
		ActiveCollectors: string(activeCollectorsStr),
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Printf("Connecting and sending initial heartbeat to %s...", a.config.ManagerIP)
	
	ctxInit, cancelInit := context.WithTimeout(ctx, 3*time.Second)
	_, err := a.grpcClient.Heartbeat(ctxInit, info)
	cancelInit()
	if err != nil {
		log.Printf("Failed to send initial heartbeat: %v", err)
	} else {
		log.Printf("Initial heartbeat sent successfully!")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ctxTick, cancelTick := context.WithTimeout(ctx, 3*time.Second)
			_, err := a.grpcClient.Heartbeat(ctxTick, info)
			cancelTick()
			if err != nil {
				log.Printf("Failed to send heartbeat: %v", err)
			} else {
				log.Printf("Heartbeat sent successfully.")
			}
		}
	}
}

// ----- Dynamic Collectors Implementation -----

func (a *App) tailFile(ctx context.Context, path string, out chan<- *pb.EventMessage) {
	t, err := tail.TailFile(path, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		log.Printf("Error tailing %s: %v", path, err)
		return
	}
	
	hostname, _ := os.Hostname()
	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case line := <-t.Lines:
			if line != nil {
				out <- &pb.EventMessage{
					AgentId:   hostname,
					Os:        runtime.GOOS,
					LogType:   "FileTail-" + path,
					Severity:  "RAW",
					Message:   line.Text,
					Timestamp: time.Now().Unix(),
				}
			}
		}
	}
}



func (a *App) listenSyslog(ctx context.Context, port int, out chan<- *pb.EventMessage) {
	addr := net.UDPAddr{Port: port, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Printf("Failed to listen on syslog port %d: %v", port, err)
		return
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 2048)
	hostname, _ := os.Hostname()

	for {
		n, remAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // usually means ctx cancelled/closed
		}
		
		msg := string(buf[:n])

		out <- &pb.EventMessage{
			AgentId:   hostname,
			Os:        runtime.GOOS,
			LogType:   "SyslogUDP",
			Severity:  "RAW",
			Message:   fmt.Sprintf("[%s] %s", remAddr.String(), msg),
			Timestamp: time.Now().Unix(),
		}
	}
}

// getLocalIP returns the non loopback local IP of the host
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
