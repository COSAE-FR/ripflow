// +build !pfsense

package configuration

import "errors"

func NewAlternateConfiguration(path string) (*MainConfiguration, error) {
	return nil, errors.New("not implemented")
}
