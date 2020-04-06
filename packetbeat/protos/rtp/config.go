
package rtp

import (
	"github.com/elastic/beats/v7/packetbeat/config"
	"github.com/elastic/beats/v7/packetbeat/protos"
)

type rtpConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = rtpConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
