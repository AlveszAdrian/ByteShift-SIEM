package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	// ── CLI Mode ─────────────────────────────────────────────────────────────
	if len(os.Args) > 1 && (os.Args[1] == "cli" || os.Args[1] == "--cli" || os.Args[1] == "-cli") {
		// Write log to AppData to avoid Program Files permission issues
		configDir, err := os.UserConfigDir()
		logPath := "agent.log" // fallback
		if err == nil {
			logDir := configDir + "/SIEMAgent"
			os.MkdirAll(logDir, 0755)
			logPath = logDir + "/agent.log"
		}

		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			os.Stdout = logFile
			os.Stderr = logFile
			log.SetOutput(logFile) // Fix: force standard library logs to file too
		}
		
		fmt.Println("\n=======================================")
		fmt.Println("[CLI] Iniciando SIEM Agent em modo Headless...")
		
		ctx, cancel := context.WithCancel(context.Background())
		app.ctx = ctx
		
		// Setup OS signal handling for graceful shutdown in CLI mode
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\n[CLI] Encerrando Agent...")
			cancel()
			os.Exit(0)
		}()

		// Load config and start collectors quietly
		app.LoadConfig()
		app.StartCollectors()
		
		fmt.Println("[CLI] Agent rodando. Pressione Ctrl+C para parar.")
		<-ctx.Done()
		return
	}

	// ── UI Mode (Wails) ──────────────────────────────────────────────────────
	// Create application with options
	err := wails.Run(&options.App{
		Title:  "SIEM Agent",
		Width:  900,
		Height: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 8, G: 14, B: 26, A: 255},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
