package sudp

import (
	"crypto/ecdsa"
	"fmt"
	"net"
)

type channels struct {
	netRx  chan *pktbuff
	userRx chan *message
	userTx chan *message
	errUTx chan error
	errNRx chan error
	exit   chan bool
}

func (c *channels) init(conn *net.UDPConn, addr *net.UDPAddr) {
	c.netRx, c.errNRx = ptkRxRoutine(conn, addr)
	c.userRx = make(chan *message, 10)
	c.userTx = make(chan *message)
	c.errUTx = make(chan error)
	c.exit = make(chan bool)

}

func (c *channels) close() {
	close(c.exit)
	close(c.userRx)
	select {
	case _, ok := <-c.userTx:
		if ok {
			close(c.userTx)
			c.errUTx <- fmt.Errorf("Connection close")
			close(c.errUTx)
		}
	default:
		close(c.userTx)
		close(c.errUTx)
	}
}

type Conn struct {
	vaddr   uint16
	conn    *net.UDPConn
	private *ecdsa.PrivateKey
	ch      channels
	err     chan error
	open    stat
}

type message struct {
	buff []byte
	addr uint16
}
