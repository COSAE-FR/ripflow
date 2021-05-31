package main

const defaultConfigFileLocation = "/etc/ripflow/ripflow.yml"

type Config struct {
	File string `usage:"configuration file" default:"/etc/ripflow/ripflow.yml"`
}
