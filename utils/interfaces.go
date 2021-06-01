// +build !linux,!freebsd

package utils

import "errors"

func NetInterfaceUp(iface net.Interface) error {
	return errors.New("not implemented")
}
