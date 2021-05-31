package pfsense

import "github.com/COSAE-FR/riputils/pfsense/configuration/helpers"

type RipflowConfig struct {
	Enable           helpers.YesNoBool `xml:"enable"`
	CollectorAddress string            `xml:"collectoraddress"`
	CollectorPort    uint16            `xml:"collectorport"`
}

type RipflowCapture struct {
	Enable      helpers.YesNoBool `xml:"enable"`
	Interface   string            `xml:"interface"`
	Filter      string            `xml:"filter"`
	Description string            `xml:"description"`
}
