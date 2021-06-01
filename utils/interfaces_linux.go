package utils

import (
	"net"
	"os/exec"
)

func NetInterfaceUp(iface net.Interface) error {
	cmd := exec.Command("ip", "link", "set", iface.Name, "up")
	return cmd.Run()
}
