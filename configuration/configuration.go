package configuration

import (
	"github.com/COSAE-FR/ripflow/utils"
	"github.com/COSAE-FR/riputils/common/logging"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const (
	defaultExporterPort  = 9999
	defaultMaxFlows      = 65536
	defaultActiveTimeout = 1800
	defaultIdleTimeout   = 15
)

type ExporterConfig struct {
	Host string
	Port uint16
}

func (c *ExporterConfig) check(logger *log.Entry) error {
	if c.Port == 0 {
		c.Port = defaultExporterPort
	}
	return nil
}

type FlowsConfig struct {
	Max           uint32
	IdleTimeout   uint32
	ActiveTimeout uint32
}

func (c *FlowsConfig) check(logger *log.Entry) error {
	if c.Max == 0 {
		c.Max = uint32(defaultMaxFlows)
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = uint32(defaultIdleTimeout)
	}
	if c.ActiveTimeout == 0 {
		c.ActiveTimeout = uint32(defaultActiveTimeout)
	}
	return nil
}

type InterfaceConfig struct {
	Name   string `yaml:"-"`
	Filter string
}

func (i *InterfaceConfig) check(name string, logger *log.Entry) error {
	i.Name = name
	return nil
}

type MainConfiguration struct {
	Logging       logging.Config             `yaml:"logging"`
	Exporter      ExporterConfig             `yaml:"exporter"`
	Cache         FlowsConfig                `yaml:"cache"`
	Interfaces    map[string]InterfaceConfig `yaml:"interfaces"`
	Log           *log.Entry                 `yaml:"-"`
	logFileWriter *os.File
	path          string
}

func (c *MainConfiguration) check() error {
	for name, i := range c.Interfaces {
		err := i.check(name, c.Log)
		if err != nil {
			c.Log.Errorf("error in %s configuration", name)
		}
		c.Interfaces[name] = i
	}
	if err := c.Exporter.check(c.Log); err != nil {
		return err
	}
	if err := c.Cache.check(c.Log); err != nil {
		return err
	}
	return nil
}

func (c *MainConfiguration) setUpLog() {
	c.Logging.App = utils.Name
	c.Logging.Version = utils.Version
	c.Logging.Component = "config_loader"
	c.Logging.FileMaxSize = 80
	c.Logging.FileMaxBackups = 10
	c.Log = logging.SetupLog(c.Logging)
}

func (c *MainConfiguration) Read() error {
	if _, err := os.Stat(c.path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	yamlFile, err := os.Open(c.path)
	if err != nil {
		return err
	}
	defer func() {
		_ = yamlFile.Close()
	}()
	byteValue, err := ioutil.ReadAll(yamlFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(byteValue, c)
}

func New(path string) (*MainConfiguration, error) {
	config := MainConfiguration{
		path: path,
	}
	err := config.Read()
	if err != nil {
		return &config, err
	}
	config.setUpLog()
	err = config.check()
	return &config, err
}
