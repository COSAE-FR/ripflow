package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

const (
	netflow5HeaderSize = 24
	netflow5RecordSize = 48
	exportBufferSize   = 1400
)

type Exporter struct {
	Input          chan Flow
	lastFlow       *Flow
	usedBufferSize uint32
	TotalFlowCount uint32
	BaseTime       time.Time
	buffer         []byte
	connection     net.Conn
	killSwitch     chan int
	log            *log.Entry
}

func NewExporter(destinationAddress string, destinationPort uint16, maxFlows uint32, logger *log.Entry) (*Exporter, error) {
	logger = logger.WithField("component", "exporter")
	connection, err := net.Dial("udp4",
		fmt.Sprintf("%s:%d", destinationAddress, destinationPort))
	if err != nil {
		return nil, err
	}
	exporter := Exporter{
		Input:      make(chan Flow, maxFlows),
		connection: connection,
		buffer:     make([]byte, exportBufferSize),
		killSwitch: make(chan int, 0),
		log:        logger,
	}
	return &exporter, nil
}

func (e *Exporter) Listen() {
	for {
		select {
		case <-e.killSwitch:
			e.log.Info("Received a listener kill switch")
			return
		case flow := <-e.Input:
			err := e.ExportNetflow5(flow)
			if err != nil {
				e.log.Errorf("Cannot export flow: %s", err)
			}
		}
	}
}

func (e *Exporter) Start() error {
	go e.Listen()
	return nil
}

func (e *Exporter) Stop() error {
	e.killSwitch <- 1
	if err := e.flushBuffer(); err != nil {
		e.log.Errorf("Cannot flush exporter buffer: %s", err)
	}
	err := e.connection.Close()
	if err != nil {
		return err
	}
	return nil
}

func (e *Exporter) ExportNetflow5(flow Flow) error {
	if flow.key.ipVersion != 4 {
		e.log.Debugf("Cannot export non IPv4 flow in Netflow V5: %s", flow.String())
		return errors.New(fmt.Sprintf("IP version %d not supported in Netflow V5", flow.key.ipVersion))
	}
	// Create Netflow v5 header
	if e.usedBufferSize == 0 &&
		(e.usedBufferSize+netflow5HeaderSize <= exportBufferSize) {
		binary.BigEndian.PutUint16(e.buffer[0:], uint16(5))  // NetFlow v5 Header constant value
		e.buffer[20] = uint8(0)                              // engine type
		e.buffer[21] = uint8(0)                              // engine id
		binary.BigEndian.PutUint16(e.buffer[22:], uint16(0)) // sample rate
		e.usedBufferSize = netflow5HeaderSize
	}
	e.lastFlow = &flow
	if e.usedBufferSize+netflow5RecordSize <= exportBufferSize {
		flow.SerializeNetflow5(e.buffer[e.usedBufferSize:],
			e.BaseTime)
		e.usedBufferSize += netflow5RecordSize
	}
	// header update
	if e.usedBufferSize+netflow5RecordSize > exportBufferSize {
		return e.flushBuffer()
	}
	return nil
}

func (e *Exporter) flushBuffer() error {
	if e.usedBufferSize > netflow5HeaderSize && e.lastFlow != nil {
		flowCount := uint16((exportBufferSize - netflow5HeaderSize) / netflow5RecordSize)
		e.TotalFlowCount += uint32(flowCount)
		binary.BigEndian.PutUint16(e.buffer[2:], flowCount)
		binary.BigEndian.PutUint32(e.buffer[4:],
			uint32(e.lastFlow.end.Sub(e.BaseTime).Nanoseconds()/int64(time.Millisecond)))
		binary.BigEndian.PutUint32(e.buffer[8:], uint32(e.lastFlow.end.Unix()))
		binary.BigEndian.PutUint32(e.buffer[12:],
			uint32(e.lastFlow.end.UnixNano()-e.lastFlow.end.Unix()*int64(time.Nanosecond)))
		binary.BigEndian.PutUint32(e.buffer[16:], e.TotalFlowCount)
		_, err := e.connection.Write(e.buffer[:e.usedBufferSize]) // UDP Send
		e.usedBufferSize = netflow5HeaderSize
		return err
	}
	return nil
}
