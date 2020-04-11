package rtp

type rtpError struct {
	message string
}

func (e *rtpError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.message
}

var (
	headerTooShort         = &rtpError{message: "Header length does not meet minimum length"}
	extendedHeaderTooShort = &rtpError{message: "Extended header specified but no extended header found"}
	unsupportedVersion     = &rtpError{message: "Only RTP version 2 is supported"}
)
