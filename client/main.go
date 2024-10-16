package main

import (
	"fmt"
	"net"
	"sudp"
	"time"
)

func main() {
	pub, e := sudp.PublicKeyFromPemFile("sdtl_public.pem")
	if e != nil {
		fmt.Println(e)
		return
	}
	pri, e := sudp.PrivateFromPemFile("private.pem")
	if e != nil {
		fmt.Println(e)
		return
	}

	a, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:7000")
	s, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:")
	laddr := sudp.LocalAddr{
		VirtualAddress: 1001,
		NetworkAddress: s,
		PrivateKey:     pri,
	}
	raddr := sudp.RemoteAddr{
		VirtualAddress: 0,
		NetworkAddress: a,
		PublicKey:      pub,
	}

	c, e := sudp.Connect(&laddr, &raddr)
	fmt.Println(c, e)
	if e != nil {
		return
	}
	for {
		c.Send([]byte("Send"))
		data, _ := c.Recv()
		fmt.Println(string(data))
		time.Sleep(time.Second)
	}

}
