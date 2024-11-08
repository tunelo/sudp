package main

import (
	"flag"
	"fmt"
	"net"
	"sudp"
	"time"
)

func main() {
	mode := flag.String("mode", "client", "Run in client or server mode")
	flag.Parse()
	if *mode == "server" {
		laddr, raddr, err := sudp.ParseConfig("sudp_config.json")
		if err != nil {
			fmt.Println(err)
			return
		}

		server, err := sudp.Listen(laddr, raddr)
		if err != nil {
			fmt.Println(err)
			return
		}
		for {
			buff, addr, err := server.RecvFrom()
			if err != nil {
				fmt.Println(err)
				return
			}
			server.SendTo(buff, addr)
		}
	} else {

		private, _ := sudp.PrivateFromPemFile("client_private.pem")
		public, _ := sudp.PublicKeyFromPemFile("server_public.pem")

		addr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:7000")
		laddr := sudp.LocalAddr{
			VirtualAddress: 1001,
			PrivateKey:     private,
			NetworkAddress: nil,
		}
		raddr := sudp.RemoteAddr{
			SharedHmacKey:  []byte("password"),
			PublicKey:      public,
			VirtualAddress: 0,
			NetworkAddress: addr,
		}

		conn, err := sudp.Connect(&laddr, &raddr, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		i := 0
		for {
			conn.Send([]byte(fmt.Sprintf("Message %d", i)))
			b, e := conn.Recv()
			fmt.Println(string(b), e)
			i = i + 1
			time.Sleep(100 * time.Millisecond)
		}
	}
}
