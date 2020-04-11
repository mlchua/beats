package rtp

import (
	"github.com/elastic/beats/v7/packetbeat/config"
)

type rtpConfig struct {
	config.ProtocolCommon `config:",inline"`
	IncludeExtensions     bool `config:"include_extensions"`
	IncludePayload        bool `config:"include_payload"`
}

var (
	defaultConfig = rtpConfig{
		IncludeExtensions: true,
		IncludePayload:    false,
	}
)
