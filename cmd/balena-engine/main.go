package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/containerd/containerd/cmd/containerd"
	containerdShimRuncV2 "github.com/containerd/containerd/cmd/containerd-shim-runc-v2"
	"github.com/containerd/containerd/cmd/ctr"
	"github.com/docker/cli/cmd/docker"
	"github.com/docker/docker/cmd/dockerd"
	"github.com/docker/docker/pkg/reexec"
	"github.com/opencontainers/runc"

	"os"
	filepath "path/filepath"
)

func main() {
	if reexec.Init() {
		return
	}

	command := filepath.Base(os.Args[0])

	go func() {
		for range time.Tick(30 * time.Second) {
			debug.FreeOSMemory()
		}
	}()

	switch command {
	case "balena", "balena-engine":
		runtime.GOMAXPROCS(1)
		debug.SetGCPercent(5)
		docker.Main()
	case "balenad", "balena-engine-daemon":
		runtime.GOMAXPROCS(2)
		dockerd.Main()
	case "balena-containerd", "balena-engine-containerd":
		runtime.GOMAXPROCS(1)
		containerd.Main()
	case "balena-containerd-shim-runc-v2":
		runtime.GOMAXPROCS(1)
		containerdShimRuncV2.Main()
	case "balena-containerd-ctr", "balena-engine-containerd-ctr":
		runtime.GOMAXPROCS(1)
		debug.SetGCPercent(5)
		ctr.Main()
	case "balena-runc", "balena-engine-runc":
		runtime.GOMAXPROCS(1)
		runc.Main()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command: %v\n", command)
		os.Exit(1)
	}
}
