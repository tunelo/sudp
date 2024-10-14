package sudp

import (
	"fmt"
	"net"
	"time"
)

type pktbuff struct {
	addr *net.UDPAddr
	buff []byte
	size int
}

func allocPktbuff() *pktbuff {
	pkt := pktbuff{
		addr: nil,
		size: 0,
		buff: make([]byte, 2048),
	}
	return &pkt
}

func (p *pktbuff) head(n int) []byte {
	if n > p.size {
		return nil
	}
	ret := p.buff[:n]
	p.buff = p.buff[n:]
	p.size -= n
	return ret
}

func (p *pktbuff) tail(n int) []byte {
	if p.size+n > len(p.buff) {
		return nil
	}
	ret := p.buff[p.size : p.size+n]
	p.size += n
	return ret
}

func (p *pktbuff) pktSend(conn *net.UDPConn) error {
	if p.addr == nil {
		return fmt.Errorf("invalid destination")
	}
	_, e := conn.WriteToUDP(p.buff[0:p.size], p.addr)
	return e
}

func pktRecv(conn *net.UDPConn, from *net.UDPAddr, deadline *time.Time) (*pktbuff, error) {
	var (
		n int
		a *net.UDPAddr
		e error
	)
	pkt := allocPktbuff()
	if deadline != nil {
		conn.SetReadDeadline(*deadline)
	}
	for {
		n, a, e = conn.ReadFromUDP(pkt.buff)
		if e != nil {
			return nil, e
		}

		if from != nil && from.String() != a.String() {
			continue
		}
		break
	}
	pkt.size = n
	pkt.addr = a
	return pkt, nil
}

func ptkRxRoutine(conn *net.UDPConn, addr *net.UDPAddr) chan *pktbuff {
	io := make(chan *pktbuff)
	go func() {
		for {
			p, e := pktRecv(conn, addr, nil)
			if e != nil {
				io <- nil
				return
			}
			io <- p
		}
	}()
	return io
}
