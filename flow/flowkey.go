package flow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"hash/fnv"
	"net"
)

type FlowKey struct {
	sourceIPAddress          net.IP // NetFlow version 1, 5, 7, 8(FullFlow)
	destinationIPAddress     net.IP // NetFlow version 1, 5, 7, 8(FullFlow)
	flowLabelIPv6            uint32
	fragmentIdentification   uint32
	sourceTransportPort      uint16 // NetFlow version 1, 5, 7, 8(FullFlow)
	destinationTransportPort uint16 // NetFlow version 1, 5, 7, 8(FullFlow)
	icmpTypeCode             uint16 // filling DST_PORT field when version is 1, 5, 7, 8
	vlanId                   uint16
	sourceMacAddress         [6]byte
	destinationMacAddress    [6]byte
	protocolIdentifier       uint8 // NetFlow version 1, 5, 7, 8(FullFlow)
	ipClassOfService         uint8 // NetFlow version 1, 5, 7, 8(FullFlow)
	ipVersion                uint8
}

func (fk FlowKey) SortKeyHeader() []byte {
	buf := make([]byte, 48)

	firstBuffer := make([]byte, 24)
	copy(firstBuffer[0:], fk.sourceIPAddress.To16())
	binary.BigEndian.PutUint16(firstBuffer[16:], fk.sourceTransportPort)
	secondBuffer := make([]byte, 24)
	copy(secondBuffer[0:], fk.destinationIPAddress.To16())
	binary.BigEndian.PutUint16(secondBuffer[16:], fk.destinationTransportPort)

	transportComparison := bytes.Compare(firstBuffer, secondBuffer)
	if transportComparison > 0 {
		copy(firstBuffer[18:], fk.sourceMacAddress[0:6])
		copy(secondBuffer[18:], fk.destinationMacAddress[0:6])
		copy(buf[0:], firstBuffer[0:24])
		copy(buf[24:], secondBuffer[0:24])
	} else if transportComparison < 0 {
		copy(firstBuffer[18:], fk.sourceMacAddress[0:6])
		copy(secondBuffer[18:], fk.destinationMacAddress[0:6])
		copy(buf[0:], secondBuffer[0:24])
		copy(buf[24:], firstBuffer[0:24])
	} else {
		if bytes.Compare(fk.sourceMacAddress[0:6], fk.destinationMacAddress[0:6]) >= 0 {
			copy(firstBuffer[18:], fk.sourceMacAddress[0:6])
			copy(secondBuffer[18:], fk.destinationMacAddress[0:6])
			copy(buf[0:], firstBuffer[0:24])
			copy(buf[24:], secondBuffer[0:24])
		} else {
			copy(firstBuffer[18:], fk.sourceMacAddress[0:6])
			copy(secondBuffer[18:], fk.destinationMacAddress[0:6])
			copy(buf[0:], secondBuffer[0:24])
			copy(buf[24:], firstBuffer[0:24])
		}
	}
	return buf
}

func (fk FlowKey) SerializeKey() []byte {
	buf := make([]byte, 55)
	copy(buf[0:], fk.SortKeyHeader())
	binary.BigEndian.PutUint16(buf[48:], fk.icmpTypeCode>>8)
	binary.BigEndian.PutUint16(buf[50:], fk.vlanId)
	buf[52] = fk.protocolIdentifier
	buf[53] = fk.ipClassOfService
	buf[54] = fk.ipVersion
	return buf
}

func (fk FlowKey) Hash() uint64 {
	hash := fnv.New64a()
	_, err := hash.Write(fk.SerializeKey())
	if err != nil {
		log.Errorf("cannot create key for flow key: %s (%s)", err, fk.String())
	}
	return hash.Sum64()
}

func (fk FlowKey) String() string {
	return fmt.Sprintf("sIP:%s, dIP:%s, flowlabel: %d, fragmentID: %d, sPort:%d, dPort:%d, icmp:%d, vlan:%d, Proto:%d, TOS:%d, ipver:%d",
		fk.sourceIPAddress.String(), fk.destinationIPAddress.String(),
		fk.flowLabelIPv6, fk.fragmentIdentification,
		fk.sourceTransportPort, fk.destinationTransportPort, fk.icmpTypeCode, fk.vlanId,
		fk.protocolIdentifier, fk.ipClassOfService, fk.ipVersion)
}
