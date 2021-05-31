// +build freebsd,pfsense

package main

const defaultConfigFileLocation = "/conf/config.xml"

type Config struct {
	File string `usage:"configuration file" default:"/conf/config.xml"`
}
