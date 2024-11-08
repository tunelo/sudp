package sudp

import (
	"crypto/ecdsa"
	"fmt"
	"net"
)

type RemoteAddr struct {
	VirtualAddress uint16
	PublicKey      *ecdsa.PublicKey
	SharedHmacKey  []byte
	NetworkAddress *net.UDPAddr
}

type LocalAddr struct {
	VirtualAddress uint16
	PrivateKey     *ecdsa.PrivateKey
	NetworkAddress *net.UDPAddr
}

func (a *RemoteAddr) String() string {
	ok := a.PublicKey != nil
	return fmt.Sprintf("remote: %s,%d - Public Key: %t", a.NetworkAddress.String(), a.VirtualAddress, ok)
}

func (a *LocalAddr) String() string {
	ok := a.PrivateKey != nil
	return fmt.Sprintf("local: %s,%d - Private Key: %t", a.NetworkAddress.String(), a.VirtualAddress, ok)
}
