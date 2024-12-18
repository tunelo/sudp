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
	buf := pkt.head(hdrsz)
	src, dst := hdrSrcDst(buf)

	peer, ok := s.peerMap[src]
	if !ok || dst != s.vaddr {
		return nil, newError("invalid source - message drop", nil)
	}

	hdr, e := hdrLoad(buf, peer.hmackey)
	if e != nil {
		return nil, newError("invalid header - message drop", e)
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
	tick := time.NewTicker(time.Second)
	for {
		select {
		case <-s.ch.exit:
			goto exit
		case pkt := <-s.ch.netRx:
			if pkt == nil {
				s.open.setStat(statClose)
				s.err <- fmt.Errorf("unexpected close")
				return
			}
			hdr, e := s.filterPacket(pkt)
			if e != nil {
				log(Warn, fmt.Sprintf("filter: %v", e))
				continue
			}
			peer, _ := s.peerMap[hdr.src]
			e = peer.handlePacket(hdr, pkt, s.private, s.ch.userRx, s.conn)
			if e != nil {
				log(Warn, fmt.Sprintf("at package handle - %v", e))
			}
		case e := <-s.ch.errNRx:
			s.open.setStat(statClose)
			s.err <- fmt.Errorf("at reception %v -> panic", e)
			return
		case msg := <-s.ch.userTx:
			peer, ok := s.peerMap[msg.addr]
			if !ok || !peer.ready {
				s.ch.errUTx <- newError("not ready", nil)
				continue
			}
			e := peer.sendDataPacket(s.vaddr, msg.buff, s.conn)
			if e != nil {
				s.ch.errUTx <- newError("sending data packet:", e)
				continue
			}
			s.ch.errUTx <- nil

		case <-tick.C:
			for _, peer := range s.peerMap {
				if peer.ready && time.Now().Sub(peer.ttlm) > 5*time.Second {
					log(Info, fmt.Sprintf("last activity for %d more than 5 sec ago - close connection", peer.vaddr))
					peer.epochs.init()
					peer.naddr = nil
					peer.ready = false
					peer.tsync = nil
					peer.ttlm = time.Time{}
				}
			}
		}

	}
exit:
	s.open.setStat(statClose)
	s.conn.Close()
	for {
		select {
		case _, ok := <-s.ch.netRx:
			if !ok {
				s.err <- nil
				s.ch.close()
				return
			}
		case e, ok := <-s.ch.errNRx:
			if ok {
				s.err <- e
				s.ch.close()
				return
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
			vaddr:   addr.VirtualAddress,
			pubkey:  addr.PublicKey,
			hmackey: addr.SharedHmacKey,
		}
		server.peerMap[addr.VirtualAddress].epochs.init()
	}

	server.ch.init(conn, nil)
	server.open.setStat(statOpen)
	go server.serve()
	return &server, nil
}

func (s *ServerConn) Close() {
	if s != nil && s.open.isOpen() {
		s.ch.exit <- true
		<-s.err
	}
}

func (s *ServerConn) RecvFrom() ([]byte, uint16, error) {
	if s == nil || !s.open.isOpen() {
		return nil, 0, fmt.Errorf("server closed")
	}
	msg := <-s.ch.userRx
	if msg == nil {
		return nil, 0, fmt.Errorf("server closed")
	}
	return msg.buff, msg.addr, nil
}

func (s *ServerConn) SendTo(buff []byte, addr uint16) error {
	if s == nil || !s.open.isOpen() {
		return fmt.Errorf("server closed")
	}
	s.ch.userTx <- &message{
		buff: buff,
		addr: addr,
	}
	return <-s.ch.errUTx
}
