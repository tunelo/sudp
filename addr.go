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
	pkok := a.PublicKey != nil
	hmok := a.SharedHmacKey != nil
	return fmt.Sprintf("remote: %s,%d - Public Key: %t - Header Hmac: %t", a.NetworkAddress.String(), a.VirtualAddress, pkok, hmok)
}

func (a *LocalAddr) String() string {
	ok := a.PrivateKey != nil
	if a.NetworkAddress == nil {
		return fmt.Sprintf("local: %s,%d - Private Key: %t", "0.0.0.0:0", a.VirtualAddress, ok)
	}
	return fmt.Sprintf("local: %s,%d - Private Key: %t", a.NetworkAddress.String(), a.VirtualAddress, ok)
}
