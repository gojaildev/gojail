package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arkrix/gojail/pkg/config"
	"github.com/arkrix/gojail/pkg/sandbox"
	"github.com/arkrix/gojail/pkg/server"
)

func main() {
	// Re-exec child hook for namespace containment
	if len(os.Args) >= 3 && os.Args[1] == "__init_child__" {
		if err := sandbox.InitChild(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error in child init: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Re-exec hook for joining active container namespaces
	if len(os.Args) >= 3 && os.Args[1] == "__init_exec__" {
		var payload struct {
			TargetPID int      `json:"target_pid"`
			Command   string   `json:"command"`
			Args      []string `json:"args"`
			Env       []string `json:"env"`
		}
		if err := json.Unmarshal([]byte(os.Args[2]), &payload); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing exec payload: %v\n", err)
			os.Exit(1)
		}

		if err := sandbox.ExecInContainer(payload.TargetPID, payload.Command, payload.Args, payload.Env); err != nil {
			fmt.Fprintf(os.Stderr, "Error executing in container: %v\n", err)
			os.Exit(1)
		}
		return
	}

	configPath := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gojaild] Configuration error: %v\n", err)
		os.Exit(1)
	}

	d := server.NewDaemon(cfg)
	if err := d.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[gojaild] Fatal startup error: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	fmt.Printf("\n[gojaild] Received signal %v, initiating shutdown...\n", sig)
	d.Stop()
}
