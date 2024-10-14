package sudp

import (
	"crypto/ecdsa"
	"net"
)

type channels struct {
	netRx  chan *pktbuff
	userRx chan *message
	userTx chan *message
	errTx  chan error
}

func (c *channels) init(conn *net.UDPConn, addr *net.UDPAddr) {
	c.netRx = ptkRxRoutine(conn, addr)
	c.userRx = make(chan *message, 10)
	c.userTx = make(chan *message)
	c.errTx = make(chan error)
}

func (c *channels) close() {
	close(c.netRx)
	close(c.userRx)
	close(c.userTx)
	close(c.errTx)
}

type Conn struct {
	vaddr   uint16
	conn    *net.UDPConn
	private *ecdsa.PrivateKey
	ch      channels
	err     chan error
}

type message struct {
	buff []byte
	addr uint16
}
