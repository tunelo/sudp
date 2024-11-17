package main

import (
	"flag"
	"fmt"
	"sudp"
	"time"
)

func main() {
	mode := flag.String("mode", "client", "Run in client or server mode")
	flag.Parse()
	if *mode == "server" {
		config, err := sudp.LoadServerConfig("server.json")
		if err != nil {
			fmt.Println(err)
			return
		}
		laddr, err := config.LocalAddress()
		if err != nil {
			fmt.Println(err)
			return
		}

		raddr, err := config.PeersAddresses()
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
		config, err := sudp.LoadClientConfig("1000_config.json")
		if err != nil {
			fmt.Println(err)
			return
		}
		laddr, err := config.LocalAddress()
		if err != nil {
			fmt.Println(err)
			return
		}

		raddr, err := config.ServerAddress()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(laddr.String())
		fmt.Println(raddr.String())
		conn, err := sudp.Connect(laddr, raddr, nil)
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
