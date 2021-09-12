package packets

import (
	"github.com/LuckyC4t/pppoe-hijack-go/internal/global"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
)

type Packet struct {
	DstMac    net.HardwareAddr
	Payload   []byte
	Code      layers.PPPoECode
	SessionId uint16
	Protocol  layers.EthernetType
	Length    uint16
}

func (p Packet) Send() {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       utils.GetMACAddr(global.Device),
			DstMAC:       p.DstMac,
			EthernetType: p.Protocol,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      p.Code,
			SessionId: p.SessionId,
			Length:    p.Length,
		},
		gopacket.Payload(p.Payload),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = global.Handle.WritePacketData(buffer.Bytes())
}
