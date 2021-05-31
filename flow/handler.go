package flow

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"net"
)

type PacketLayers struct {
	eth   layers.Ethernet
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6
}

type ParserParameters struct {
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	dot1q   *layers.Dot1Q
	ip4     *layers.IPv4
	ip6     *layers.IPv6
	tcp     *layers.TCP
	udp     *layers.UDP
	sctp    *layers.SCTP
	icmp4   *layers.ICMPv4
	icmp6   *layers.ICMPv6
	decoded []gopacket.LayerType
}

type PacketHandler struct {
	handle     *pcap.Handle
	iface      *net.Interface
	Worker     chan Flow
	killSwitch chan int
	log        *log.Entry
}

func (handler *PacketHandler) SetFilter(filter string) error {
	return handler.handle.SetBPFFilter(filter)
}

func (handler *PacketHandler) Close() {
	handler.handle.Close()
}

func NewHandler(iface *net.Interface, worker chan Flow, logger *log.Entry) (*PacketHandler, error) {
	handler := &PacketHandler{
		iface: iface,
		log: logger.WithFields(log.Fields{
			"component": "capture",
			"interface": iface.Name,
		}),
	}
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		handler.log.Errorf("Unable to open packet capture on interface %s", iface.Name)
		return handler, err
	}
	handler.handle = handle
	handler.Worker = worker
	handler.killSwitch = make(chan int, 0)
	return handler, nil
}

func (handler *PacketHandler) Listen() {
	handler.log.Debugf("Listening on interface %s", handler.iface.Name)
	src := gopacket.NewPacketSource(handler.handle, layers.LayerTypeEthernet)
	in := src.Packets()
	var pl PacketLayers
	pp := ParserParameters{
		parser:  gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &pl.eth, &pl.dot1q, &pl.ip4, &pl.ip6, &pl.tcp, &pl.udp, &pl.icmp4, &pl.icmp6),
		decoded: []gopacket.LayerType{},
		eth:     &pl.eth,
		dot1q:   &pl.dot1q,
		ip4:     &pl.ip4,
		ip6:     &pl.ip6,
		tcp:     &pl.tcp,
		udp:     &pl.udp,
		icmp4:   &pl.icmp4,
		icmp6:   &pl.icmp6,
	}
	pp.parser.IgnoreUnsupported = true
	for {
		select {
		case <-handler.killSwitch:
			handler.log.Info("Received a listener kill switch")
			return
		case packet := <-in:
			err := pp.parser.DecodeLayers(packet.Data(), &pp.decoded)
			if err != nil {
				handler.log.Tracef("Error when decoding packet: %s", err)
			}
			flow := NewFlow(pp, packet.Metadata().CaptureInfo, *handler.iface)
			if flow.key.ipVersion == 0 {
				handler.log.Tracef("Not an IP packet: %s, layers: %v", flow.String(), pp.decoded)
				continue
			}
			handler.Worker <- flow
		}
	}
}

func (handler *PacketHandler) Start() error {
	go handler.Listen()
	return nil
}

func (handler *PacketHandler) Stop() error {
	handler.killSwitch <- 1
	handler.handle.Close()
	return nil
}
