package utils

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
)

func ShowInterfaces() {
	allInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, item := range allInterfaces {
		fmt.Printf("%+v\n", item)
	}
}
