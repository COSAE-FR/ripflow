// +build pfsense

package configuration

import (
	"encoding/xml"
	"errors"
	"github.com/COSAE-FR/ripflow/configuration/pfsense"
	"github.com/COSAE-FR/riputils/common/logging"
	"github.com/COSAE-FR/riputils/pfsense/configuration"
	"github.com/COSAE-FR/riputils/pfsense/configuration/sections/packages"
	"io/ioutil"
	"path/filepath"
)

const defaultPfSenseLogFile = "/var/log/ripflow/flow.log"

func NewAlternateConfiguration(path string) (*MainConfiguration, error) {
	if filepath.Ext(path) == ".xml" {
		pfConfig, err := GetConfigurationFromPfSense(path)
		if err == nil {
			pfConfig.Log.Debug("Starting in pfSense mode")
			return pfConfig, nil
		}
	}
	return nil, errors.New("configuration not compatible")
}

type proxyPackageConfiguration struct {
	packages.BasePackageConfig
	Ripflow         *pfsense.RipflowConfig   `xml:"netflow>config"`
	RipflowCaptures []pfsense.RipflowCapture `xml:"netflowcaptures>config"`
}

type ripSenseConfiguration struct {
	configuration.BaseConfiguration
	Packages proxyPackageConfiguration `xml:"installedpackages"`
}

func GetConfigurationFromPfSense(path string) (*MainConfiguration, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pfConf := &ripSenseConfiguration{}

	err = xml.Unmarshal(data, &pfConf)
	if err != nil {
		return nil, err
	}
	if pfConf.Packages.Ripflow == nil {
		return nil, errors.New("no netflow section in configuration")
	}
	if !pfConf.Packages.Ripflow.Enable {
		return nil, errors.New("netflow is disabled in configuration")
	}

	conf := &MainConfiguration{
		Logging: logging.Config{
			Level: "error",
			File:  defaultPfSenseLogFile,
		},
		Exporter: ExporterConfig{
			Host: pfConf.Packages.Ripflow.CollectorAddress,
			Port: pfConf.Packages.Ripflow.CollectorPort,
		},
	}
	conf.setUpLog()
	conf.Interfaces = map[string]InterfaceConfig{}

	for _, ifaceConfig := range pfConf.Packages.RipflowCaptures {
		if !ifaceConfig.Enable {
			continue
		}
		iface, err := pfConf.GetPhysicalInterfaceName(ifaceConfig.Interface)
		if err != nil {
			conf.Log.Errorf("cannot get physical interface for %s in interfaces config", ifaceConfig.Interface)
		}
		capturing := InterfaceConfig{
			Name:   iface,
			Filter: ifaceConfig.Filter,
		}
		conf.Interfaces[iface] = capturing
	}
	if len(conf.Interfaces) == 0 {
		return nil, errors.New("no capturing interface configured")
	}
	err = conf.check()
	return conf, err
}
