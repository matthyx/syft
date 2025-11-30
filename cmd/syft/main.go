package main

import (
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	_ "modernc.org/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli"
	"github.com/anchore/syft/cmd/syft/internal"
)

// applicationName is the non-capitalized name of the application (do not change this)
const applicationName = "syft"

// all variables here are provided as build-time arguments, with clear default values
var (
	version        = internal.NotProvided
	buildDate      = internal.NotProvided
	gitCommit      = internal.NotProvided
	gitDescription = internal.NotProvided
)

func main() {
	// Create a CPU profile file
	cpuProfileFile, err := os.Create("cpu.prof")
	if err != nil {
		panic(err)
	}
	defer cpuProfileFile.Close()
	// Start CPU profiling
	if err := pprof.StartCPUProfile(cpuProfileFile); err != nil {
		panic(err)
	}
	defer pprof.StopCPUProfile()

	go func() {
		os.Mkdir("pprof", 0755)
		for {
			// Create a memory profile file
			memProfileFile, err := os.Create(fmt.Sprintf("pprof/%s.prof", time.Now().Format("2006-01-02T15:04:05")))
			if err != nil {
				panic(err)
			}
			// Write memory profile to file
			if err := pprof.WriteHeapProfile(memProfileFile); err != nil {
				panic(err)
			}
			memProfileFile.Close()
			time.Sleep(time.Second)
		}
	}()

	app := cli.Application(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	app.Run()
}
