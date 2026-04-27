package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"runtime"
	"time"

	pb "agent-ui/proto"

	"github.com/0xrawsec/golang-etw/etw"
)

// Known ETW Provider GUIDs
var (
	// Microsoft-Windows-Kernel-Process
	ProcessProviderGUID = etw.MustParseProvider("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
	// Microsoft-Windows-Kernel-Network
	NetworkProviderGUID = etw.MustParseProvider("7dd42a49-5329-4832-8dfd-43d979153a88")
)

// StartETW inicia a sessão do Event Tracing for Windows
func StartETW(ctx context.Context, out chan<- *pb.EventMessage) {
	sessionName := "SIEM-Agent-Session"

	// Create and start session
	session := etw.NewRealTimeSession(sessionName)
	if err := session.Start(); err != nil {
		// Log the error but we might just need to attach if it's already running
		log.Printf("[ETW] Session start returned: %v. (Are you running as Administrator?)", err)
	}
	// Try to enable providers
	if err := session.EnableProvider(ProcessProviderGUID); err != nil {
		log.Printf("[ETW] Failed to enable Process provider: %v", err)
	}
	if err := session.EnableProvider(NetworkProviderGUID); err != nil {
		log.Printf("[ETW] Failed to enable Network provider: %v", err)
	}

	consumer := etw.NewRealTimeConsumer(ctx)
	consumer.FromSessions(session)

	go func() {
		err := consumer.Start()
		if err != nil {
			log.Printf("[ETW] Consumer error: %v", err)
		}
	}()

	log.Println("[ETW] Listener Started. Monitoring Process and Network events.")

	hostname, _ := os.Hostname()

	for {
		select {
		case <-ctx.Done():
			log.Println("[ETW] Listener Stopping...")
			session.Stop()
			consumer.Stop()
			return
		case e := <-consumer.Events:
			if e == nil {
				continue
			}

			// Add provider name if missing
			providerName := e.System.Provider.Name
			if providerName == "" {
				if e.System.Provider.Guid == "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716" || e.System.Provider.Guid == "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}" {
					providerName = "Microsoft-Windows-Kernel-Process"
				} else if e.System.Provider.Guid == "7DD42A49-5329-4832-8DFD-43D979153A88" || e.System.Provider.Guid == "{7dd42a49-5329-4832-8dfd-43d979153a88}" {
					providerName = "Microsoft-Windows-Kernel-Network"
				} else {
					providerName = e.System.Provider.Guid
				}
			}

			props := make(map[string]interface{})
			// Copy EventData
			for k, v := range e.EventData {
				props[k] = v
			}
			// Inject Metadata
			props["EventID"] = e.System.EventID
			props["Provider"] = providerName
			props["ProcessID"] = e.System.Execution.ProcessID
			props["ThreadID"] = e.System.Execution.ThreadID

			msgBytes, _ := json.Marshal(props)

			out <- &pb.EventMessage{
				AgentId:   hostname,
				Os:        runtime.GOOS,
				LogType:   "WinEvent-ETW",
				Severity:  "INFO",
				Message:   string(msgBytes),
				Timestamp: time.Now().Unix(),
			}
		}
	}
}
