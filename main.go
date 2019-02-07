package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
	clientMap    = make(map[string]int)
)

func main() {
	flag.StringVar(&device, "i", "", "network interface")
	flag.Parse()
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func printPacketInfo(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if reflect.DeepEqual(ethernetPacket.Contents[12:], []byte{136, 99}) {
			switch ethernetPacket.Payload[1] {
			case 9:
				fmt.Println("find!")
				sendPadoPacket(ethernetPacket.SrcMAC, ethernetPacket.Payload)
				break
			case 25:
				sendPadsPacket(ethernetPacket.SrcMAC, ethernetPacket.Payload)
				break
			}
		} else if reflect.DeepEqual(ethernetPacket.Contents[12:], []byte{136, 100}) {
			switch string(ethernetPacket.Payload[6:8]) {
			case "\xc0\x21":
				sendLcpReq(ethernetPacket.SrcMAC, ethernetPacket.Payload)
				break
			case "\xc0\x23":
				getPapInfo(ethernetPacket.Payload)
				break
			}
		}
	}
}

func getMACAddr() net.HardwareAddr {
	interfaces, _ := net.Interfaces()
	for _, netInterface := range interfaces {
		if netInterface.Name == device {
			return netInterface.HardwareAddr
		}
	}
	return net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
}

func sendPadoPacket(srcMAC net.HardwareAddr, raw []byte) {
	hostUniq := padiFindHostUniq(raw)
	payload := []byte("\x01\x01\x00\x00\x01\x02\x00\x06aaaaaa\x01\x04\x00\x14\xee\x2d\x61\x89\x27\x87\x9c\x6d\xae\x82\xf5\x14\x8c\x21\x24\xa9\xdb\x09\x00\x00")
	if hostUniq != nil {
		payload = append(payload, hostUniq...)
	}
	sendPacket(srcMAC, payload, 0x07, 0x00, 0x8863, uint16(len(payload)))
	fmt.Println("send Pado packet...")
}

func sendPadsPacket(srcMAC net.HardwareAddr, raw []byte) {
	hostUniq := padiFindHostUniq(raw)
	payload := []byte("\x01\x01\x00\x00\x01\x02\x00\x06aaaaaa")
	if hostUniq != nil {
		payload = append(payload, hostUniq...)
	}
	sendPacket(srcMAC, payload, 0x65, 0x01, 0x8863, uint16(len(payload)))
	fmt.Println("send Pads packet...")
}

func padiFindHostUniq(raw []byte) []byte {
	re, _ := regexp.Compile("\x01\x03")
	if re.Match(raw) {
		nIdx := re.FindIndex(raw)[0]
		nLen := int(binary.BigEndian.Uint16(raw[nIdx+2:nIdx+4]))
		return append([]byte{0x01, 0x03}, raw[nIdx+2:nIdx+4+nLen]...)
	}
	return nil
}

func sendLcpReq(srcMAC net.HardwareAddr, raw []byte) {
	if raw[8] == 1 {
		fmt.Println("Received LCP-Config-Req")
		if _, ok := clientMap[string(raw)]; !ok {
			go sendLcpRejectPacket(srcMAC, raw)
			go sendLcpReqPacket(srcMAC, raw)
			clientMap[string(raw)] = 1
		}
		sendLcpAckPacket(srcMAC, raw)
	}
}

func sendLcpRejectPacket(srcMAC net.HardwareAddr, body []byte) {
	raw := make([]byte, len(body))
	copy(raw, body)
	defer func() { raw = nil }()
	raw[8] = 0x04
	length := len(raw[8:])
	sendPacket(srcMAC, raw[6:], 0x00, 0x01, 0x8864, uint16(length))
	fmt.Println("send LCP Reject packet...")
}

func sendLcpReqPacket(srcMAC net.HardwareAddr, body []byte) {
	raw := make([]byte, len(body))
	copy(raw, body)
	defer func() { raw = nil }()
	raw[9] = 0x01
	raw[11] = 0x12
	raw = append(raw, []byte("\x01\x04\x05\xc8\x03\x04\xc0\x23\x05\x06\x5e\x63\x0a\xb8\x00\x00\x00\x00")...)
	length := len(raw) - len(raw[0:8])
	sendPacket(srcMAC, raw[6:8+length], 0x00, 0x01, 0x8864, uint16(length))
	fmt.Println("send LCP Request packet...")
}

func sendLcpAckPacket(srcMAC net.HardwareAddr, body []byte) {
	raw := make([]byte, len(body))
	copy(raw, body)
	defer func() { raw = nil }()
	raw[8] = 0x02
	length := raw[5]
	sendPacket(srcMAC, raw[6:], 0x00, 0x01, 0x8864, uint16(length))
	fmt.Println("send LCP Ack packet...")
}

func getPapInfo(body []byte) {
	fmt.Println("---------------------------------------")
	fmt.Println("username:", string(body[13:13+body[12]]))
	fmt.Println("password:", string(body[14+body[12]:]))
	fmt.Println("---------------------------------------")
	os.Exit(0)
}

func sendPacket(srcMAC net.HardwareAddr, payload []byte, code layers.PPPoECode, sessionid uint16, protocol layers.EthernetType, length uint16) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       srcMAC,
			EthernetType: protocol,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      code,
			SessionId: sessionid,
			Length:    length,
		},
		gopacket.Payload(payload),
	)
	handle.WritePacketData(buffer.Bytes())
}
