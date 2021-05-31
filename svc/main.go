package main

import (
	"github.com/COSAE-FR/ripflow/configuration"
	"github.com/COSAE-FR/ripflow/flow"
	"github.com/COSAE-FR/ripflow/utils"
	"github.com/COSAE-FR/riputils/common/logging"
	log "github.com/sirupsen/logrus"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/service.v2"
	"net"
)

type Daemon struct {
	Configuration *configuration.MainConfiguration
	Captures      []flow.PacketHandler
	Exporter      *flow.Exporter
	Cache         *flow.Cache
}

func (d Daemon) Start() error {
	err := d.Exporter.Start()
	if err != nil {
		return err
	}
	err = d.Cache.Start()
	if err != nil {
		return err
	}
	for _, svr := range d.Captures {
		svr := svr
		err := svr.Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (d Daemon) Stop() error {
	for _, svr := range d.Captures {
		_ = svr.Stop()
	}
	_ = d.Cache.Stop()
	_ = d.Exporter.Stop()
	return nil
}

func New(cfg Config) (*Daemon, error) {
	config, err := configuration.New(cfg.File)
	if err != nil {
		return nil, err
	}
	daemon := Daemon{Configuration: config}

	daemon.Exporter, err = flow.NewExporter(config.Exporter.Host, config.Exporter.Port, config.Cache.Max, config.Log)
	if err != nil {
		return nil, err
	}

	daemon.Cache, err = flow.NewCache(config.Cache.Max, config.Cache.IdleTimeout, config.Cache.ActiveTimeout, daemon.Exporter.Input, config.Log)
	if err != nil {
		return nil, err
	}

	for _, iface := range daemon.Configuration.Interfaces {
		logger := daemon.Configuration.Log.WithFields(log.Fields{
			"app":       utils.Name,
			"version":   utils.Version,
			"component": "capture",
			"interface": iface.Name,
		})
		netInterface, err := net.InterfaceByName(iface.Name)
		if err != nil {
			return &daemon, err
		}
		srv, err := flow.NewHandler(netInterface, daemon.Cache.Input, logger)
		if err != nil {
			return &daemon, err
		}
		if len(iface.Filter) > 0 {
			if err = srv.SetFilter(iface.Filter); err != nil {
				log.Errorf("Cannot set BPF filter %s: %s", iface.Filter, err)
			}
		}
		daemon.Captures = append(daemon.Captures, *srv)
	}
	return &daemon, nil
}

func main() {
	logger := logging.SetupLog(logging.Config{
		Level:     "error",
		App:       utils.Name,
		Version:   utils.Version,
		Component: "main",
	})

	cfg := Config{}

	configurator := &easyconfig.Configurator{
		ProgramName: utils.Name,
	}

	err := easyconfig.Parse(configurator, &cfg)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	if len(cfg.File) == 0 {
		cfg.File = defaultConfigFileLocation
	}
	logger.Debugf("Starting %s daemon", utils.Name)
	service.Main(&service.Info{
		Name:      utils.Name,
		AllowRoot: true,
		NewFunc: func() (service.Runnable, error) {
			return New(cfg)
		},
	})
}
