package actions

import (
	"fmt"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/packets"
	"github.com/google/gopacket/layers"
)

func sendPapAuthReject(eth *layers.Ethernet, ppp *layers.PPP) {
	identifier := ppp.Payload[1]
	message := []byte("bye")
	payload := append([]byte{0x03, identifier, 0x00, byte(5 + len(message)), byte(len(message))}, message...)
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
	fmt.Println("send Pap Auth Reject packet...")
}
