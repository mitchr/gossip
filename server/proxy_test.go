package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/pires/go-proxyproto"
)

func TestCanConnectWithPROXYHeader(t *testing.T) {
	conf := &Config{
		Network: "cafeteria",
		Name:    "gossip",
		Port:    ":6667",
	}
	conf.TLS.Port = ":6697"
	conf.TLS.Proxies = []string{"127.0.0.1"}

	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, _ := net.Dial("tcp", ":6697")
	defer c.Close()

	header := &proxyproto.Header{
		Version:           1,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        c.LocalAddr(),
		DestinationAddr:   c.RemoteAddr(),
	}
	_, err = header.WriteTo(c)
	if err != nil {
		t.Fatal(err)
	}

	c.Write([]byte("nick a\r\n"))
	c.Write([]byte("user u s e r\r\n"))
	r := bufio.NewReader(c)
	resp, _ := r.ReadBytes('\n')
	assertResponse(resp, ":gossip 001 a :Welcome to the cafeteria IRC Network a!u@localhost\r\n", t)
}

func TestRejectUnknownProxyIp(t *testing.T) {
	conf := &Config{
		Network: "cafeteria",
		Name:    "gossip",
		Port:    ":6667",
	}
	conf.TLS.Port = ":6697"
	conf.TLS.Proxies = []string{"127.0.0.2"}

	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, _ := net.Dial("tcp", ":6697")
	defer c.Close()

	header := &proxyproto.Header{
		Version:           1,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        c.LocalAddr(),
		DestinationAddr:   c.RemoteAddr(),
	}
	_, err = header.WriteTo(c)
	if err != nil {
		t.Fatal(err)
	}

	c.Write([]byte("nick a\r\n"))
	c.Write([]byte("user u s e r\r\n"))
	r := bufio.NewReader(c)
	resp, _ := r.ReadBytes('\n')

	if !strings.Contains(string(resp), "ERROR") {
		t.Error(string(resp))
	}
}

func TestProperIpResponseInWHOX(t *testing.T) {
	conf := &Config{
		Network: "cafeteria",
		Name:    "gossip",
		Port:    ":6667",
	}
	conf.TLS.Port = ":6697"
	conf.TLS.Proxies = []string{"127.0.0.2"}

	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	proxyListener, err := net.Listen("tcp", "127.0.0.2:6000")
	if err != nil {
		t.Fatal(err)
	}
	proxyListener = &proxyproto.Listener{Listener: proxyListener}

	// setup proxy server on 127.0.0.2
	go func() {
		c, err := proxyListener.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}

		// when testing here our local address will be 127.0.0.1 but we can
		// use a custom Dialer that will mock our address as 127.0.0.2
		localDialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
		fwd, err := localDialer.Dial("tcp", "127.0.0.1:6697")
		if err != nil {
			fmt.Println(err)
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			_, err = io.Copy(fwd, c)
			if err != nil {
				fmt.Println(err)
				return
			}
			wg.Done()
		}()

		go func() {
			_, err = io.Copy(c, fwd)
			if err != nil {
				fmt.Println(err)
				return
			}
			wg.Done()
		}()

		wg.Wait()
	}()

	c, err := net.Dial("tcp", "127.0.0.2:6000")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Write([]byte("nick a\r\n"))
	c.Write([]byte("user u s e r\r\n"))
	r := bufio.NewReader(c)
	readLines(r, 13)

	c.Write([]byte("WHO a %i\r\n"))
	resp, _ := r.ReadBytes('\n')
	assertResponse(resp, ":gossip 354 a 127.0.0.2\r\n", t)
}
