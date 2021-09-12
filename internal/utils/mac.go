package utils

import (
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
)

func GetMACAddr(device string) net.HardwareAddr {
	interfaces, _ := net.Interfaces()
	for _, netInterface := range interfaces {
		if netInterface.Name == getNameByDevice(device) {
			return netInterface.HardwareAddr
		}
	}
	return net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
}

func getNameByDevice(device string) string {
	devs, _ := pcap.FindAllDevs()
	ip := ""
	for _, dev := range devs {
		if dev.Name == device {
			if len(dev.Addresses) > 0 {
				ip = dev.Addresses[0].IP.String()
			}
		}
	}

	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if strings.Contains(addr.String(), ip) {
				return i.Name
			}
		}
	}

	return ""
}
