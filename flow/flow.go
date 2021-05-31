package flow

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

// https://www.iana.org/assignments/ipfix/ipfix.xml 6:tcpControlBits
const (
	tcpControlBitsFIN uint16 = 0x0001
	tcpControlBitsSYN uint16 = 0x0002
	tcpControlBitsRST uint16 = 0x0004
	tcpControlBitsPSH uint16 = 0x0008
	tcpControlBitsACK uint16 = 0x0010
	tcpControlBitsURG uint16 = 0x0020
	tcpControlBitsECE uint16 = 0x0040
	tcpControlBitsCWR uint16 = 0x0080
	tcpControlBitsNS  uint16 = 0x0100
)

// https://www.iana.org/assignments/ipfix/ipfix.xml 136:flowEndReason
const (
	flowEndReasonIdleTimeout     uint8 = 0x01
	flowEndReasonActiveTimeout   uint8 = 0x02
	flowEndReasonEndOfFlow       uint8 = 0x03
	flowEndReasonForceEnd        uint8 = 0x04
	flowEndReasonLackOfResources uint8 = 0x05
)

func copyIP(ip net.IP) net.IP {
	destination := make(net.IP, len(ip))
	copy(destination, ip)
	return destination
}

func tcpFlag(t *layers.TCP) uint16 {
	var f uint16
	if t.FIN {
		f |= tcpControlBitsFIN
	}
	if t.SYN {
		f |= tcpControlBitsSYN
	}
	if t.RST {
		f |= tcpControlBitsRST
	}
	if t.PSH {
		f |= tcpControlBitsPSH
	}
	if t.ACK {
		f |= tcpControlBitsACK
	}
	if t.URG {
		f |= tcpControlBitsURG
	}
	if t.ECE {
		f |= tcpControlBitsECE
	}
	if t.CWR {
		f |= tcpControlBitsCWR
	}
	if t.NS {
		f |= tcpControlBitsNS
	}
	return f
}

type Flow struct {
	octetDeltaCount  uint64
	packetDeltaCount uint64
	start            time.Time
	end              time.Time
	key              FlowKey
	tcpControlBits   uint16 // NetFlow version 1, 5, 7
	flowEndReason    uint8
	ifIndex          uint16
}

func NewFlow(parameters ParserParameters, info gopacket.CaptureInfo, iface net.Interface) Flow {
	var flow Flow
	key := &flow.key
	flow.ifIndex = uint16(iface.Index)
	for _, layer := range parameters.decoded {
		switch layer {
		case layers.LayerTypeEthernet:
			copy(key.sourceMacAddress[0:6], parameters.eth.SrcMAC)
			copy(key.destinationMacAddress[0:6], parameters.eth.DstMAC)
		case layers.LayerTypeDot1Q:
			key.vlanId = parameters.dot1q.VLANIdentifier
		case layers.LayerTypeIPv4:
			key.ipVersion = 4
			key.protocolIdentifier = uint8(parameters.ip4.Protocol)
			key.ipClassOfService = parameters.ip4.TOS
			key.sourceIPAddress = copyIP(parameters.ip4.SrcIP)
			key.destinationIPAddress = copyIP(parameters.ip4.DstIP)
			key.fragmentIdentification = uint32(parameters.ip4.Id)
		case layers.LayerTypeIPv6:
			key.ipVersion = 6
			key.protocolIdentifier = uint8(parameters.ip6.NextHeader)
			key.ipClassOfService = parameters.ip6.TrafficClass
			key.sourceIPAddress = copyIP(parameters.ip6.SrcIP)
			key.destinationIPAddress = copyIP(parameters.ip6.DstIP)
			key.flowLabelIPv6 = parameters.ip6.FlowLabel
		case layers.LayerTypeTCP:
			flow.tcpControlBits = tcpFlag(parameters.tcp)
			key.sourceTransportPort = uint16(parameters.tcp.SrcPort)
			key.destinationTransportPort = uint16(parameters.tcp.DstPort)
		case layers.LayerTypeUDP:
			key.sourceTransportPort = uint16(parameters.udp.SrcPort)
			key.destinationTransportPort = uint16(parameters.udp.DstPort)
		case layers.LayerTypeICMPv4:
			key.icmpTypeCode = uint16(parameters.icmp4.TypeCode)
		case layers.LayerTypeICMPv6:
			key.icmpTypeCode = uint16(parameters.icmp6.TypeCode)
		}
	}
	flow.packetDeltaCount = 1
	flow.octetDeltaCount = uint64(info.Length)
	flow.start, flow.end = info.Timestamp, info.Timestamp
	return flow
}

func (f *Flow) String() string {
	return fmt.Sprintf("key:%s, tcpFlag:%d, octets:%d, packet:%d, start:%s, end:%s, iface:%d",
		f.key.String(), f.tcpControlBits, f.octetDeltaCount,
		f.packetDeltaCount, f.start.String(), f.end.String(), f.ifIndex)
}

func (f *Flow) SerializeNetflow5(buf []byte, baseTime time.Time) {
	source := f.key.sourceIPAddress.To4()
	if source == nil {
		log.Errorf("Flow source IP is not a valid IPv4: %s", f.String())
	}
	destination := f.key.destinationIPAddress.To4()
	if destination == nil {
		log.Errorf("Flow destination IP is not a valid IPv4: %s", f.String())
	}
	copy(buf[0:], source)
	copy(buf[4:], destination)
	binary.BigEndian.PutUint32(buf[8:], uint32(0)) // Nexthop Address, cannot lookup always 0
	binary.BigEndian.PutUint16(buf[12:], f.ifIndex)
	binary.BigEndian.PutUint16(buf[14:], uint16(0)) // Output IFIndex, cannot lookup always 0
	binary.BigEndian.PutUint32(buf[16:], uint32(f.packetDeltaCount))
	binary.BigEndian.PutUint32(buf[20:], uint32(f.octetDeltaCount))
	binary.BigEndian.PutUint32(buf[24:], uint32(f.start.Sub(baseTime).Nanoseconds()/int64(time.Millisecond)))
	binary.BigEndian.PutUint32(buf[28:], uint32(f.end.Sub(baseTime).Nanoseconds()/int64(time.Millisecond)))
	if f.key.icmpTypeCode > 0 {
		binary.BigEndian.PutUint16(buf[32:], uint16(0))
		binary.BigEndian.PutUint16(buf[34:], f.key.icmpTypeCode)
	} else {
		binary.BigEndian.PutUint16(buf[32:], f.key.sourceTransportPort)
		binary.BigEndian.PutUint16(buf[34:], f.key.destinationTransportPort)
	}

	buf[36] = uint8(0) //padding
	buf[37] = uint8(f.tcpControlBits)
	buf[38] = f.key.protocolIdentifier
	buf[39] = f.key.ipClassOfService
	binary.BigEndian.PutUint16(buf[40:], uint16(0)) // Source AS, cannot lookup always 0
	binary.BigEndian.PutUint16(buf[42:], uint16(0)) // Destination AS, cannot lookup always 0
	buf[44] = uint8(0)                              // Source Address Prefix Length
	buf[45] = uint8(0)                              // Destination Address Prefix Length
	binary.BigEndian.PutUint16(buf[46:], uint16(0)) // padding
}
