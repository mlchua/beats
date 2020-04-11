package rtp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/protos"
)

const (
	MIN_HEADER_LENGTH          = 12
	MIN_EXTENDED_HEADER_LENGTH = 4

	// Masks for the first octet
	VERSION_BITMASK    = 0b10000000
	PADDING_BITMASK    = 0b00100000
	EXTENSION_BITMASK  = 0b00010000
	CSRC_COUNT_BITMASK = 0b00001111

	// Masks for the second octet
	MARKER_BITMASK  = 0b10000000
	PAYLOAD_BITMASK = 0b01111111
)

// rtpPlugin application level protocol analyzer plugin
type rtpPlugin struct {
	ports  protos.PortsConfig
	report protos.Reporter
	log    *logp.Logger

	includeExtensions bool
	includePayload    bool
}

type rtpHeader struct {
	version        uint8
	hasPadding     bool
	hasExtension   bool
	csrcCount      uint8
	hasMarker      bool
	payloadType    uint8
	sequenceNumber uint16
	timestamp      uint32
	ssrc           uint32
	csrc           []uint32
}

func (h *rtpHeader) String() string {
	return fmt.Sprintf("rtpHeader version[%d] hasPadding[%t] hasExtension[%t] csrcCount[%d] hasMarker[%t] payloadType[%d] sequenceNumber[%d] timestamp[%d] ssrc[%d], csrc[%v]",
		h.version, h.hasPadding, h.hasExtension, h.csrcCount, h.hasMarker, h.payloadType, h.sequenceNumber, h.timestamp, h.ssrc, h.csrc)
}

type rtpExtendedHeader struct {
	profile   uint16
	length    uint16
	extension []byte
}

func (h *rtpExtendedHeader) String() string {
	return fmt.Sprintf("rtpExtendedHeader profile[%d] length[%t] extension[%v]",
		h.profile, h.length, h.extension)
}

type rtpPacket struct {
	header         rtpHeader
	extendedHeader rtpExtendedHeader
	payload        []byte
}

func (p *rtpPacket) String() string {
	return fmt.Sprintf("rtpPacket header[%v] extendedHeader[%v] payload[%v]",
		p.header, p.extendedHeader, p.payload)
}

func init() {
	protos.Register("rtp", New)
}

// New create and initializes a new {protocol} protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &rtpPlugin{
		log:    logp.NewLogger("rtp"),
		report: results,
	}
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
	rtp.includeExtensions = config.IncludeExtensions
	rtp.includePayload = config.IncludePayload
	return nil
}

func (rtp *rtpPlugin) GetPorts() []int {
	return rtp.ports.Ports
}

func (rtp *rtpPlugin) ParseUDP(pkt *protos.Packet) {
	defer rtp.log.Recover("Parse rtp exception")

	packetSize := len(pkt.Payload)

	rtp.log.Debugf("Parsing RTP packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)

	parsedPkt, err := rtp.parseRTPData(pkt.Payload)
	if err != nil {
		// This means that the packet is either malformed or
		// a non-RTP packet sent to an RTP port
		rtp.log.Warnf("%s", err.Error())
		return
	}
	rtp.publishPacket(parsedPkt, pkt)
}

func (rtp *rtpPlugin) parseRTPData(rawData []byte) (*rtpPacket, error) {
	header, remaining, err := rtp.parseRTPHeader(rawData)
	if err != nil {
		return nil, err
	}
	rtp.log.Debug("Parsed RTP header: ", header)

	packet := &rtpPacket{header: *header}

	if header.hasExtension {
		extendedHeader, payload, err := rtp.parseRTPExtendedHeader(remaining)
		if err != nil {
			return nil, err
		}
		packet.extendedHeader = *extendedHeader
		packet.payload = payload

		rtp.log.Debug("Parsed RTP extended header: ", extendedHeader)
	} else {
		packet.payload = remaining
	}

	return packet, nil
}

func (rtp *rtpPlugin) parseRTPHeader(rawData []byte) (*rtpHeader, []byte, error) {
	if len(rawData) < MIN_HEADER_LENGTH {
		return nil, nil, headerTooShort
	}

	firstOctet := rawData[0]
	if firstOctet&VERSION_BITMASK != VERSION_BITMASK {
		return nil, nil, unsupportedVersion
	}

	hasPadding := firstOctet&PADDING_BITMASK == PADDING_BITMASK
	hasExtension := firstOctet&EXTENSION_BITMASK == EXTENSION_BITMASK
	csrcCount := firstOctet & CSRC_COUNT_BITMASK

	secondOctet := rawData[1]
	hasMarker := secondOctet&MARKER_BITMASK == MARKER_BITMASK
	payloadType := secondOctet & PAYLOAD_BITMASK

	sequenceNumber := binary.BigEndian.Uint16(rawData[2:4])

	timestamp := binary.BigEndian.Uint32(rawData[4:8])
	ssrc := binary.BigEndian.Uint32(rawData[8:12])

	csrc := make([]uint32, csrcCount)
	for i := 0; i < int(csrcCount); i++ {
		start := 12 + (i * 4)
		csrc[i] = binary.BigEndian.Uint32(rawData[start : start+4])
	}

	header := &rtpHeader{
		version:        2,
		hasPadding:     hasPadding,
		hasExtension:   hasExtension,
		csrcCount:      csrcCount,
		hasMarker:      hasMarker,
		payloadType:    payloadType,
		sequenceNumber: sequenceNumber,
		timestamp:      timestamp,
		ssrc:           ssrc,
		csrc:           csrc,
	}
	return header, rawData[12+(csrcCount*4):], nil
}

func (rtp *rtpPlugin) parseRTPExtendedHeader(rawData []byte) (*rtpExtendedHeader, []byte, error) {
	if len(rawData) < MIN_EXTENDED_HEADER_LENGTH {
		return nil, nil, extendedHeaderTooShort
	}

	profile := binary.BigEndian.Uint16(rawData[0:2])
	length := binary.BigEndian.Uint16(rawData[2:4])

	stopOffset := 4 + (length * 4)
	extension := rawData[4:stopOffset]

	extendedHeader := &rtpExtendedHeader{
		profile:   profile,
		length:    length,
		extension: extension,
	}
	return extendedHeader, rawData[stopOffset:], nil
}

func (rtp *rtpPlugin) publishPacket(pkt *rtpPacket, orig *protos.Packet) {
	evt, pbf := pb.NewBeatEvent(orig.Ts)

	// source/destination (note: this protocol does not produce a bi-flow.)
	src, dst := common.MakeEndpointPair(orig.Tuple.BaseTuple, nil)
	pbf.SetSource(&src)
	pbf.SetDestination(&dst)
	pbf.Source.Bytes = int64(len(orig.Payload))

	pbf.Event.Start = orig.Ts
	pbf.Event.Dataset = "rtp"
	pbf.Network.Transport = "udp"
	pbf.Network.Protocol = pbf.Event.Dataset

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	fields["status"] = common.OK_STATUS

	header := common.MapStr{
		"version":         pkt.header.version,
		"padding":         pkt.header.hasPadding,
		"extension":       pkt.header.hasExtension,
		"csrc_count":      pkt.header.csrcCount,
		"marker":          pkt.header.hasMarker,
		"payload_type":    pkt.header.payloadType,
		"sequence_number": pkt.header.sequenceNumber,
		"timestamp":       pkt.header.timestamp,
		"ssrc":            pkt.header.ssrc,
		"csrc_list":       pkt.header.csrc,
	}

	rtpFields := common.MapStr{}
	rtpFields.Put("header", header)

	if rtp.includeExtensions && pkt.header.hasExtension {
		extendedHeader := common.MapStr{
			"profile":   pkt.extendedHeader.profile,
			"length":    pkt.extendedHeader.length,
			"extension": hex.EncodeToString(pkt.extendedHeader.extension),
		}
		rtpFields.Put("extensionHeader", extendedHeader)
	}
	if rtp.includePayload {
		rtpFields.Put("payload", hex.EncodeToString(pkt.payload))
	}

	fields.Put("rtp", rtpFields)

	rtp.report(evt)
}
