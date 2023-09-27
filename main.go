package main

import (
	"fmt"
	device_integrity "github.com/muzzapp/skipper/filters/device-integrity"
	"github.com/muzzapp/skipper/filters/teapot"
	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper"
	"github.com/zalando/skipper/config"
	"github.com/zalando/skipper/filters"
	"runtime"
)

var (
	version string
	commit  string
)

func main() {
	cfg := config.NewConfig()
	if err := cfg.Parse(); err != nil {
		log.Fatalf("Error processing config: %s", err)
	}

	if cfg.PrintVersion {
		fmt.Printf(
			"Skipper version %s (commit: %s, runtime: %s)",
			version, commit, runtime.Version(),
		)

		return
	}

	log.SetLevel(cfg.ApplicationLogLevel)
	o := cfg.ToOptions()

	o.CustomFilters = []filters.Spec{
		teapot.Spec,
		device_integrity.Spec,
	}

	log.Fatal(skipper.Run(o))
}
