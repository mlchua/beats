package rtp

import (
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/beats/v7/packetbeat/protos"
)

// rtpPlugin application level protocol analyzer plugin
type rtpPlugin struct {
	ports protos.PortsConfig
}

var (
	debugf = logp.MakeDebug("rtp")

	// use isDebug/isDetailed to guard debugf/detailedf to minimize allocations
	// (garbage collection) when debug log is disabled.
	isDebug = false
)

func init() {
	protos.Register("rtp", New)
}

// New create and initializes a new {protocol} protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &rtpPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (rtp *rtpPlugin) init(results protos.Reporter, config *rtpConfig) error {
	rtp.setFromConfig(config)
	return nil
}

func (rtp *rtpPlugin) setFromConfig(config *rtpConfig) error {
	rtp.ports.Ports = config.Ports
	return nil
}

func (rtp *rtpPlugin) GetPorts() []int {
	return rtp.ports.Ports
}

func (rtp *rtpPlugin) ParseUDP(pkt *protos.Packet) {
	defer logp.Recover("RTP ParseUdp")
	packetSize := len(pkt.Payload)

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)
	err := decodeRTPData(pkt.Payload)
	if err != nil {
		// This means that the packet is either malformed or
		// a non-RTP packet
		debugf("%s", err.Error())
		return
	}
}

const (
	MIN_HEADER_LENGTH = 12

	VERSION_BITMASK    = 0b10000000
	PADDING_BITMASK    = 0b00100000
	EXTENSION_BITMASK  = 0b00010000
	CSRC_COUNT_BITMASK = 0b00001111
)

func decodeRTPData(rawData []byte) error {
	if len(rawData) < MIN_HEADER_LENGTH {
		return headerTooShort
	}

	firstOctet := rawData[0]
	if firstOctet&VERSION_BITMASK != VERSION_BITMASK {
		return unsupportedVersion
	}

	hasPadding := firstOctet&PADDING_BITMASK == PADDING_BITMASK
	hasExtension := firstOctet&EXTENSION_BITMASK == EXTENSION_BITMASK
	debugf("RTP packet has padding: %t, extension: %t.",
		hasPadding, hasExtension)
	return nil
}
