package sudp

import (
	"fmt"
	"net"
	"time"
)

type ServerConn struct {
	peerMap map[uint16]*peer
	Conn
}

func (s *ServerConn) filterPacket(pkt *pktbuff) (*hdr, error) {
	hdr, e := hdrLoad(pkt.head(hdrsz))
	if e != nil || hdr.dst != s.vaddr {
		return nil, newError("invalid header - message drop", e)
	}
	peer, ok := s.peerMap[hdr.src]
	if !ok || hdr.dst != s.vaddr {
		return nil, newError("invalid source - message drop", nil)
	}

	if peer.tsync == nil {
		if peer.tsync, e = newTimeSync(hdr.time); e != nil {
			return nil, newError("not in time, peer time not well configured - message drop", e)
		}
	} else if !peer.tsync.inTime(hdr.time) {
		return nil, newError(fmt.Sprintf("not in time %d, out of sync - message drop", hdr.time), nil)
	}
	return hdr, nil
}

func (s *ServerConn) serve() {
	for {
		select {
		case pkt := <-s.ch.netRx:
			if pkt == nil {
				s.err <- fmt.Errorf("unexpected close")
				return
			}
			hdr, e := s.filterPacket(pkt)
			if e != nil {
				log(Error, fmt.Sprintf("filter: %v", e))
				continue
			}
			peer, _ := s.peerMap[hdr.src]
			fmt.Println(hdr.String())
			e = peer.handlePacket(hdr, pkt, s.private, s.ch.userRx, s.conn)
			if e != nil {
				log(Error, fmt.Sprintf("at package handle - %v", e))
			}
		case msg := <-s.ch.userTx:
			peer, ok := s.peerMap[msg.addr]
			if !ok || !peer.ready {
				s.ch.errTx <- newError("not ready", nil)
				continue
			}
			e := peer.sendDataPacket(s.vaddr, msg.buff, s.conn)
			if e != nil {
				s.ch.errTx <- newError("sending data packet:", e)
				continue
			}
			s.ch.errTx <- nil
		}
		for _, peer := range s.peerMap {
			if peer.ready && time.Now().Sub(peer.ttlm) > 5*time.Second {
				peer.epochs.init()
				peer.naddr = nil
				peer.ready = false
				peer.tsync = nil
				peer.ttlm = time.Time{}
			}
		}
	}
}

func Listen(laddr *LocalAddr, raddrs []*RemoteAddr) (*ServerConn, error) {

	if laddr.PrivateKey == nil {
		return nil, fmt.Errorf("private key not present")
	}

	if laddr.NetworkAddress == nil {
		return nil, fmt.Errorf("network address not found")
	}

	conn, err := net.ListenUDP("udp4", laddr.NetworkAddress)
	if err != nil {
		return nil, err
	}

	server := ServerConn{
		Conn: Conn{
			vaddr:   laddr.VirtualAddress,
			conn:    conn,
			private: laddr.PrivateKey,
			err:     make(chan error),
		},
		peerMap: make(map[uint16]*peer),
	}

	for _, addr := range raddrs {
		if addr.PublicKey == nil {
			continue
		}
		server.peerMap[addr.VirtualAddress] = &peer{
			vaddr:  addr.VirtualAddress,
			pubkey: addr.PublicKey,
		}
		server.peerMap[addr.VirtualAddress].epochs.init()
	}

	server.ch.init(conn, nil)

	go server.serve()
	return &server, nil
}

func (s *ServerConn) RecvFrom() ([]byte, uint16) {
	msg := <-s.ch.userRx
	return msg.buff, msg.addr
}

func (s *ServerConn) SendTo(buff []byte, addr uint16) error {
	s.ch.userTx <- &message{
		buff: buff,
		addr: addr,
	}
	return <-s.ch.errTx
}
