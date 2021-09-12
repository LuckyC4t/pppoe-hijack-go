package actions

import (
	"fmt"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/global"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/packets"
	"github.com/google/gopacket/layers"
)

func sendPadsPacket(eth *layers.Ethernet, pppoe *layers.PPPoE) {
	payload := append(pppoe.Payload, global.AC_NAME...)

	packet := packets.Packet{
		DstMac:    eth.SrcMAC,
		Payload:   payload,
		Code:      layers.PPPoECodePADS,
		SessionId: 0x01,
		Protocol:  layers.EthernetTypePPPoEDiscovery,
		Length:    uint16(len(payload)),
	}

	packet.Send()
	fmt.Println("send Pads packet...")
}
