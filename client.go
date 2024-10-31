package sudp

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

type ClientConn struct {
	server *peer
	opts   *ClientOpts
	Conn
}

type ClientOpts struct {
	Tries       int
	TimeRetry   int
	EpochChange int
}

func (c *ClientConn) filterPacket(pkt *pktbuff) (*hdr, error) {
	hdr, e := hdrLoad(pkt.head(hdrsz))
	if e != nil || hdr.dst != c.vaddr {
		return nil, newError("invalid header - message drop", e)
	}
	if c.server == nil && c.server.vaddr != hdr.src || c.vaddr != hdr.dst {
		return nil, newError("invalid source - message drop", nil)
	}

	if c.server.tsync == nil {
		if c.server.tsync, e = newTimeSync(hdr.time); e != nil {
			return nil, newError("not in time - message drop", e)
		}
	} else if !c.server.tsync.inTime(hdr.time) {
		return nil, newError("not in time - message drop", e)
	}
	return hdr, nil
}

func (c *ClientConn) RemoteAddress() string {
	if c != nil {
		return c.server.naddr.String()
	}
	return ""
}

func (c *ClientConn) serve() error {
	start := make(chan time.Time)
	go func(refresh <-chan time.Time) {

		var (
			start bool
			tries int
		)

		start = true
		tries = 0
		control := time.NewTicker(500 * time.Millisecond)
		for {
			select {
			case <-c.ch.exit:
				goto exit
			case msg := <-c.ch.userTx:
				if c.server == nil || c.server.vaddr != msg.addr || !c.server.ready {
					c.ch.errUTx <- newError("not ready", nil)
					continue
				}
				e := c.server.sendDataPacket(c.vaddr, msg.buff, c.conn)
				if e != nil {
					c.ch.errUTx <- newError("sending data packet:", e)
					continue
				}
				c.ch.errUTx <- nil
			case pkt := <-c.ch.netRx:
				if pkt == nil {
					c.open = false
					c.err <- fmt.Errorf("unexpected close")
					close(c.err)
					return
				}
				hdr, e := c.filterPacket(pkt)
				if e != nil {
					log(Warn, fmt.Sprintf("filter: %v", e))
					continue
				}
				e = c.server.handlePacket(hdr, pkt, c.private, c.ch.userRx, c.conn)
				if e != nil {
					log(Warn, fmt.Sprintf("at package handle - %v", e))
				}

			case e := <-c.ch.errNRx:
				c.open = false
				c.err <- fmt.Errorf("at reception %v -> panic", e)
				close(c.err)
				return
			case <-control.C:
				if c.server.ready {
					var ctrl ctrlmessage
					epoch, _ := c.server.epochs.current()
					header := newHdr(typeCtrlMessage, uint32(epoch), c.vaddr, c.server.vaddr)
					header.len = ctrlmessagesz
					packet := allocPktbuff()
					packet.addr = c.server.naddr
					if err := header.dump(packet.tail(hdrsz)); err != nil {
						continue
					}
					ctrl.crc32 = header.crc32
					ctrl.set(KeepAlive)
					if err := ctrl.dump(packet.tail(ctrlmessagesz), c.private); err != nil {
						continue
					}
					packet.pktSend(c.conn)
				}
				if c.server.resend != nil && c.server.hndshk && time.Now().Sub(c.server.hsSent) > time.Duration(c.opts.TimeRetry)*time.Second {
					tries = tries + 1
					if tries == c.opts.Tries+1 {
						c.open = false
						c.conn.Close()
						e := <-c.ch.netRx
						for ; e != nil; e = <-c.ch.netRx {
						}
						c.ch.close()
						c.err <- fmt.Errorf("timeout")
						close(c.err)
						return
					}
					c.server.hsSent = time.Now()
					rsnd, err := c.server.resend.repack(c.private)
					if err == nil {
						rsnd.addr = c.server.naddr
						rsnd.pktSend(c.conn)
					}

				}
			case <-refresh:
				var epoch int
				tries = 0
				if pending, _ := c.server.epochs.pending(); pending != -1 {
					continue // Evaluar que hacemos aca
				}
				if c.server.epochs.cEpoch == -1 {
					epoch = rand.Intn(65536)
				} else {
					epoch = c.server.epochs.cEpoch + 1
				}
				key, err := c.server.epochs.new(epoch)
				if err != nil {
					continue
				}
				header := newHdr(typeClientHandshake, uint32(epoch), c.vaddr, c.server.vaddr)
				header.len = handshakesz
				packet := allocPktbuff()
				packet.addr = c.server.naddr
				if err = header.dump(packet.tail(hdrsz)); err != nil {
					continue
				}
				handshake := handshake{
					crc32: header.crc32,
				}
				copy(handshake.pubkey[:], key.public())
				if err = handshake.dump(packet.tail(handshakesz), c.private); err != nil {
					continue
				}
				c.server.hndshk = true
				c.server.hsSent = time.Now()
				c.server.resend = &pkthandshakeraw{
					hdr: *header,
					hsk: handshake,
				}
				packet.pktSend(c.conn)
			}
			if start && c.server.ready {
				start = false
				tries = 0
				refresh = time.NewTicker(time.Duration(c.opts.EpochChange) * time.Second).C
				c.err <- nil
			}
		}
	exit:
		c.open = false
		c.conn.Close()
		for {
			select {
			case _, ok := <-c.ch.netRx:
				if !ok {
					c.err <- nil
					c.ch.close()
					return
				}
			case e, ok := <-c.ch.errNRx:
				if ok {
					c.err <- e
					c.ch.close()
					return
				}
			}
		}
	}(start)
	start <- time.Time{}
	return <-c.err
}

func Connect(laddr *LocalAddr, raddr *RemoteAddr, opts *ClientOpts) (*ClientConn, error) {

	if raddr.NetworkAddress == nil {
		return nil, fmt.Errorf("invalid peer address")
	}
	if laddr.PrivateKey == nil || raddr.PublicKey == nil {
		return nil, fmt.Errorf("keys not present")
	}

	conn, err := net.ListenUDP("udp4", laddr.NetworkAddress)
	if err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &ClientOpts{
			TimeRetry:   2,
			Tries:       4,
			EpochChange: 30,
		}
	}

	c := &ClientConn{
		Conn: Conn{
			vaddr:   laddr.VirtualAddress,
			conn:    conn,
			private: laddr.PrivateKey,
			err:     make(chan error),
		},
		server: &peer{
			vaddr:  raddr.VirtualAddress,
			naddr:  raddr.NetworkAddress,
			pubkey: raddr.PublicKey,
		},
	}
	c.ch.init(c.conn, c.server.naddr)
	c.server.epochs.init()

	if e := c.serve(); e != nil {
		return nil, e
	}
	c.open = true
	return c, nil
}

func (s *ClientConn) GetErrors() error {
	var err error
	for e := range s.err {
		err = fmt.Errorf("%v, %v", err, e)
	}
	return err
}

func (s *ClientConn) Close() error {
	if s == nil {
		return fmt.Errorf("invalid connection")
	}
	if s.open {
		s.ch.exit <- true
	}

	return s.GetErrors()
}

func (s *ClientConn) Send(buff []byte) error {
	if s == nil || !s.open {
		return fmt.Errorf("connection closed")
	}
	s.ch.userTx <- &message{
		buff: buff,
		addr: s.server.vaddr,
	}
	return <-s.ch.errUTx
}

func (s *ClientConn) Recv() ([]byte, error) {
	if s == nil || !s.open {
		return nil, fmt.Errorf("connection closed")
	}
	msg := <-s.ch.userRx
	if msg == nil {
		return nil, fmt.Errorf("connection closed")
	}
	return msg.buff, nil
}
