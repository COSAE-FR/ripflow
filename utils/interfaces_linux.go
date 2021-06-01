package utils

import (
	"net"
	"os/exec"
)

func NetInterfaceUp(iface net.Interface) error {
	cmd := exec.Command("ip", "link", "set", iface.Name, "up")
	return cmd.Run()
}

func NetInterfaceDown(iface net.Interface) error {
	cmd := exec.Command("ip", "link", "set", iface.Name, "down")
	return cmd.Run()
}
