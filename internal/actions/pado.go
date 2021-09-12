package actions

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/global"
	"github.com/LuckyC4t/pppoe-hijack-go/internal/packets"
	"github.com/google/gopacket/layers"
)

// 发送PADO回执包
func sendPadoPacket(eth *layers.Ethernet, pppoe *layers.PPPoE) {
	payload := append(pppoe.Payload, global.AC_NAME...)

	packet := packets.Packet{
		DstMac:    eth.SrcMAC,
		Payload:   payload,
		Code:      layers.PPPoECodePADO,
		SessionId: pppoe.SessionId,
		Protocol:  layers.EthernetTypePPPoEDiscovery,
		Length:    uint16(len(payload)),
	}

	packet.Send()
	fmt.Println("send PADO packet...")
}

// 寻找客户端发送的Host-Uniq
func padiFindHostUniq(raw []byte) []byte {
	key := []byte{0x01, 0x03}
	nIdx := bytes.Index(raw, key)
	if nIdx == -1 {
		return nil
	}
	nLen := int(binary.BigEndian.Uint16(raw[nIdx+2 : nIdx+4]))
	return append(key, raw[nIdx+2:nIdx+4+nLen]...)
}
