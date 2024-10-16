package main

import (
	"fmt"
	"sudp"

	"golang.org/x/net/ipv4"
)

const (
	udplen   = 8
	overhead = ipv4.HeaderLen + 8 + sudp.HeaderLen + sudp.DataHeaderLen
)

func mtu(m int) int {
	return m - overhead
}

func main() {
	fmt.Println(mtu(1500))

	laddr, raddrs, e := sudp.ParseConfig("config.json")
	if e != nil {
		panic(e)
	}

	srv, e := sudp.Listen(laddr, raddrs)
	if e != nil {
		panic(e)
	}

	for {
		data, from, _ := srv.RecvFrom()
		fmt.Println(fmt.Sprintf("Recibido de %d %s", from, string(data)))
		srv.SendTo([]byte("Recv"), from)
	}
	//	server, e := sdtlv2.NewServer("config.json")

	//	if e != nil {
	//		fmt.Println("Error:", e)
	//		return
	//	}
	//
	// server.Listen()
	//
	//	for {
	//		b, e := server.Recv()
	//		fmt.Println("Mensajeeeee")
	//		fmt.Println(string(b), *e)
	//	}
}
