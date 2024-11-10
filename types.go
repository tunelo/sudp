package sudp

const (
	protocolVersion = 0x3

	typeData            = 0x04
	typeCtrlMessage     = 0x03
	typeServerHandshake = 0x02
	typeClientHandshake = 0x01
)
