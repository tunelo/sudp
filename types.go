package sudp

import "fmt"

const (
	protocolVersion = 0x3

	typeData            = 0x04
	typeCtrlMessage     = 0x03
	typeServerHandshake = 0x02
	typeClientHandshake = 0x01
)

var (
	libraryVersion = "0.2-rc"
)

func Version() string {
	return fmt.Sprintf("protocol: v%d, library: v%s", protocolVersion, libraryVersion)
}
