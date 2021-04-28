package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
)

func TestWriteMultiline(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, _ := net.Dial("tcp", ":6667")
	defer c.Close()

	c.Write([]byte("NICK alice\r\nUSER alice 0 0 :Alice\r\n"))
	resp, _ := bufio.NewReader(c).ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(":%s 001 alice :Welcome to the Internet Relay Network %s\r\n", s.listener.Addr(), s.clients["alice"]), t)
}

func TestRegistration(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	t.Run("RegisterClient", func(t *testing.T) {
		conn, _ := connectAndRegister("alice", "Alice Smith")
		defer conn.Close()

		// check to see if server is in correct state
		c := s.clients["alice"]
		if c.Nick != "alice" {
			t.Errorf("Nick registered incorrectly. Got %s\n", c.Nick)
		}
		if c.User != "alice" {
			t.Errorf("User registered incorrectly. Got %s\n", c.User)
		}
		if c.Realname != "Alice Smith" {
			t.Errorf("Real name registered incorrectly. Got %s\n", c.Realname)
		}
		if !c.Registered {
			t.Error("Client not registered")
		}
	})

	t.Run("NICKChange", func(t *testing.T) {
		conn, r := connectAndRegister("bob", "Bob Smith")
		defer conn.Close()

		// sender should be the same user host, but with the previous nick
		beforeChange := *s.clients["bob"]

		conn.Write([]byte("NICK dan\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s NICK :dan\r\n", beforeChange), t)
	})

	t.Run("RegisterClientModes", func(t *testing.T) {
		tests := []struct {
			name    string
			modeArg uint
			mode    client.Mode
		}{
			{"a", 4, client.Invisible},
			{"b", 8, client.Wallops},
			{"c", 12, client.Invisible | client.Wallops},
		}
		for _, v := range tests {
			conn, _ := net.Dial("tcp", ":6667")
			conn.Write([]byte("NICK " + v.name + "\r\n"))
			conn.Write([]byte(fmt.Sprintf("USER %s %v 0 :%s\r\n", v.name, v.modeArg, v.name)))
			bufio.NewReader(conn).ReadBytes('\n') // reading the response guarantees that registration finishes

			c := s.clients[v.name]
			if c.Mode != v.mode {
				t.Error("Mode set incorrectly", c.Mode, v.modeArg, v.mode)
			}
			conn.Close()
		}
	})
}

// test cases are taken from https://www.irc.com/dev/docs/refs/commands/pass
func TestPASS(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.password = "letmein"
	go s.Serve()

	t.Run("TestRegisteredWithNoPASS", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))
		r := bufio.NewReader(c)
		resp, _ := r.ReadBytes('\n')
		err, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 464 chris :Password Incorrect\r\n", s.listener.Addr()), t)
		assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.listener.Addr()), t)
		if !poll(&s.clients, 0) {
			t.Error("Could not kick client after icnorrect password")
		}
	})
	t.Run("TestPASSParamMissing", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("PASS\r\n"))

		r := bufio.NewReader(c)
		err, _ := r.ReadBytes('\n')
		// err, _ := r.ReadBytes('\n')

		assertResponse(err, fmt.Sprintf(":%s 461 * PASS :Not enough parameters\r\n", s.listener.Addr()), t)
		// assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.listener.Addr()), t)
		if !poll(&s.clients, 0) {
			t.Error("Could not kick client after icnorrect password")
		}
	})
	t.Run("TestPASSIncorrect", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("PASS opensesame\r\n"))
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))
		r := bufio.NewReader(c)
		resp, _ := r.ReadBytes('\n')
		err, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 464 chris :Password Incorrect\r\n", s.listener.Addr()), t)
		assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.listener.Addr()), t)
		if !poll(&s.clients, 0) {
			t.Error("Could not kick client after icnorrect password")
		}
	})
	t.Run("TestPASSCorrect", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("PASS letmein\r\n"))
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))

		r := bufio.NewReader(c)
		for i := 0; i < 13; i++ {
			r.ReadBytes('\n')
		}

		if !poll(&s.clients, 1) {
			t.Error("Could not register, despite correct password")
		}

		t.Run("TestPASSAlreadyRegistered", func(t *testing.T) {
			c.Write([]byte("PASS letmein\r\n"))
			err, _ := r.ReadBytes('\n')
			assertResponse(err, fmt.Sprintf(":%s 462 chris :You may not reregister\r\n", s.listener.Addr()), t)
		})
	})
}

func TestQUIT(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	t.Run("TestNoReason", func(t *testing.T) {
		c, r := connectAndRegister("alice", "Alice Smith")
		defer c.Close()
		c.Write([]byte("QUIT\r\n"))

		quitResp, _ := r.ReadBytes('\n')
		assertResponse(quitResp, "ERROR :alice quit\r\n", t)

		if !poll(&s.clients, 0) {
			t.Error("client could not quit")
		}
	})

	t.Run("TestReason", func(t *testing.T) {
		c1, r1 := connectAndRegister("bob", "Bob Smith")
		defer c1.Close()
		c2, r2 := connectAndRegister("dan", "Dan Jones")
		defer c2.Close()
		c1.Write([]byte("JOIN #l\r\n"))
		r1.ReadBytes('\n')
		c2.Write([]byte("JOIN #l\r\n"))
		r1.ReadBytes('\n')
		r2.ReadBytes('\n')
		r2.ReadBytes('\n')

		bobPrefix := s.clients["bob"].String()

		c1.Write([]byte("QUIT :Done for the day\r\n"))

		bobQuitErr, _ := r1.ReadBytes('\n')
		assertResponse(bobQuitErr, "ERROR :bob quit\r\n", t)

		danReceivesReason, _ := r2.ReadBytes('\n')
		assertResponse(danReceivesReason, fmt.Sprintf(":%s QUIT :Done for the day\r\n", bobPrefix), t)

		if !poll(&s.clients, 1) {
			t.Error("client could not quit")
		}
	})
}

func TestChannelCreation(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	c1.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')

	if !poll(&s.channels, 1) {
		t.Fatal("Could not create channel")
	}

	t.Run("TestChanNameInsensitive", func(t *testing.T) {
		c2.Write([]byte("JOIN #LOcAl\r\n"))
		resp, _ := r2.ReadBytes('\n')
		r2.ReadBytes('\n')
		r1.ReadBytes('\n') // alice reading bob's join msg

		assertResponse(resp, fmt.Sprintf(":%s JOIN #local\r\n", s.clients["bob"]), t)
	})

	t.Run("TestChannelPART", func(t *testing.T) {
		// c1 leaves, c2 should receive a PARTing message from them
		c1.Write([]byte("PART #local :Goodbye\r\n"))
		aliceResp, _ := r1.ReadBytes('\n')
		bobResp, _ := r2.ReadBytes('\n')
		assertResponse(aliceResp, fmt.Sprintf(":%s PART #local :Goodbye\r\n", s.clients["alice"]), t)
		assertResponse(bobResp, fmt.Sprintf(":%s PART #local :Goodbye\r\n", s.clients["alice"]), t)
	})

	t.Run("TestChannelDestruction", func(t *testing.T) {
		c2.Write([]byte("PART #local\r\n"))
		response, _ := r2.ReadBytes('\n')
		assertResponse(response, fmt.Sprintf(":%s PART #local\r\n", s.clients["bob"]), t)

		if !poll(&s.channels, 0) {
			t.Error("Could not destroy empty channel on PART")
		}
	})

	t.Run("TestJOIN0", func(t *testing.T) {
		c1.Write([]byte("JOIN #chan1\r\nJOIN #chan2\r\nJOIN #chan3\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')

		c1.Write([]byte("JOIN 0\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')

		c1.Write([]byte("LIST\r\n"))
		response, _ := r1.ReadBytes('\n')
		assertResponse(response, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.listener.Addr()), t)
	})
}

func TestChannelKeys(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	s.channels["#1"] = channel.New("1", channel.Remote)
	s.channels["#1"].Key = "Key1"
	s.channels["#2"] = channel.New("2", channel.Remote)
	s.channels["#2"].Key = "Key2"
	s.channels["#3"] = channel.New("3", channel.Remote)

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	c.Write([]byte("JOIN #1,#2,#3 Key1,Key2\r\n"))
	join1, _ := r.ReadBytes('\n')
	r.ReadBytes('\n')
	join2, _ := r.ReadBytes('\n')
	r.ReadBytes('\n')
	join3, _ := r.ReadBytes('\n')

	assertResponse(join1, fmt.Sprintf(":%s JOIN #1\r\n", s.clients["alice"]), t)
	assertResponse(join2, fmt.Sprintf(":%s JOIN #2\r\n", s.clients["alice"]), t)
	assertResponse(join3, fmt.Sprintf(":%s JOIN #3\r\n", s.clients["alice"]), t)
}

func TestTOPIC(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	c.Write([]byte("JOIN &test\r\n"))
	r.ReadBytes('\n')

	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :This is a test\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))

	unchanged, _ := r.ReadBytes('\n')
	assertResponse(unchanged, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.listener.Addr()), t)
	changed, _ := r.ReadBytes('\n')
	assertResponse(changed, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.listener.Addr()), t)
	retrieve, _ := r.ReadBytes('\n')
	assertResponse(retrieve, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.listener.Addr()), t)

	r.ReadBytes('\n')
	clear, _ := r.ReadBytes('\n')
	assertResponse(clear, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.listener.Addr()), t)
}

func TestKICK(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	r2.ReadBytes('\n')
	r2.ReadBytes('\n')
	c1.Write([]byte("KICK #local bob\r\n"))
	aliceKick, _ := r1.ReadBytes('\n')
	bobKick, _ := r2.ReadBytes('\n')

	// check received correct response
	assertResponse(aliceKick, fmt.Sprintf(":%s KICK #local bob :alice\r\n", s.clients["alice"]), t)
	assertResponse(bobKick, fmt.Sprintf(":%s KICK #local bob :alice\r\n", s.clients["alice"]), t)

	// check actually bob removed from channel
	if !poll(&s.channels["#local"].Members, 1) {
		t.Fail()
	}
}

func TestNAMES(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	c.Write([]byte("JOIN &test\r\n"))
	r.ReadBytes('\n')
	c.Write([]byte("NAMES &test\r\n"))
	namreply, _ := r.ReadBytes('\n')
	end, _ := r.ReadBytes('\n')

	assertResponse(namreply, fmt.Sprintf(":%s 353 alice = &test :~alice\r\n", s.listener.Addr()), t)
	assertResponse(end, fmt.Sprintf(":%s 366 alice &test :End of /NAMES list\r\n", s.listener.Addr()), t)
}

func TestLIST(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	t.Run("TestNoParams", func(t *testing.T) {
		c.Write([]byte("JOIN &test\r\n"))
		r.ReadBytes('\n')
		c.Write([]byte("LIST\r\n"))
		listReply, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')

		assertResponse(listReply, fmt.Sprintf(":%s 322 alice &test 1 :\r\n", s.listener.Addr()), t)
		assertResponse(end, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.listener.Addr()), t)
	})

	t.Run("TestParam", func(t *testing.T) {
		c.Write([]byte("JOIN &params\r\n"))
		r.ReadBytes('\n')
		c.Write([]byte("LIST &params\r\n"))
		listReply, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')

		assertResponse(listReply, fmt.Sprintf(":%s 322 alice &params 1 :\r\n", s.listener.Addr()), t)
		assertResponse(end, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.listener.Addr()), t)
	})
}

func TestMODE(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')

	t.Run("TestUserNotInChan", func(t *testing.T) {
		c2.Write([]byte("MODE #local +o bob\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 441 bob bob #local :They aren't on that channel\r\n", s.listener.Addr()), t)
	})

	c2.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	r2.ReadBytes('\n')

	c1.Write([]byte("MODE #local +k pass\r\n"))
	c1.Write([]byte("MODE #local +o bob\r\n"))
	c1.Write([]byte("MODE #local\r\n"))
	passApplied, _ := r1.ReadBytes('\n')
	opApplied, _ := r1.ReadBytes('\n')
	getModeResp, _ := r1.ReadBytes('\n')

	assertResponse(passApplied, fmt.Sprintf(":%s MODE +k pass\r\n", s.listener.Addr()), t)
	assertResponse(opApplied, fmt.Sprintf(":%s MODE +o bob\r\n", s.listener.Addr()), t)
	assertResponse(getModeResp, fmt.Sprintf(":%s 324 alice #local k\r\n", s.listener.Addr()), t)

	if s.channels["#local"].Members["bob"].Prefix != "@" {
		t.Error("Failed to set member mode")
	}

	t.Run("TestChannelModeMissingParam", func(t *testing.T) {
		c1.Write([]byte("MODE #local +l\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 461 alice :+l :Not enough parameters\r\n", s.listener.Addr()), t)
	})

	t.Run("TestUserModeMissingParam", func(t *testing.T) {
		c1.Write([]byte("MODE #local +o\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 461 alice :+o :Not enough parameters\r\n", s.listener.Addr()), t)
	})

	t.Run("TestUnknownMode", func(t *testing.T) {
		c1.Write([]byte("MODE #local +w\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 472 alice w :is unknown mode char to me for #local\r\n", s.listener.Addr()), t)
	})

	t.Run("TestRPLBANLIST", func(t *testing.T) {
		c1.Write([]byte("MODE #local +b abc\r\nMODE #local +b def\r\nMODE #local +b ghi\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		c1.Write([]byte("MODE #local +b\r\n"))
		abc, _ := r1.ReadBytes('\n')
		def, _ := r1.ReadBytes('\n')
		ghi, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')

		assertResponse(abc, fmt.Sprintf(":%s 367 alice #local abc\r\n", s.listener.Addr()), t)
		assertResponse(def, fmt.Sprintf(":%s 367 alice #local def\r\n", s.listener.Addr()), t)
		assertResponse(ghi, fmt.Sprintf(":%s 367 alice #local ghi\r\n", s.listener.Addr()), t)
		assertResponse(end, fmt.Sprintf(":%s 368 alice #local :End of channel ban list\r\n", s.listener.Addr()), t)
	})

	t.Run("TestRPLEXCEPTLIST", func(t *testing.T) {
		c1.Write([]byte("MODE #local +e abc\r\nMODE #local +e def\r\nMODE #local +e ghi\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		c1.Write([]byte("MODE #local +e\r\n"))
		abc, _ := r1.ReadBytes('\n')
		def, _ := r1.ReadBytes('\n')
		ghi, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')

		assertResponse(abc, fmt.Sprintf(":%s 348 alice #local abc\r\n", s.listener.Addr()), t)
		assertResponse(def, fmt.Sprintf(":%s 348 alice #local def\r\n", s.listener.Addr()), t)
		assertResponse(ghi, fmt.Sprintf(":%s 348 alice #local ghi\r\n", s.listener.Addr()), t)
		assertResponse(end, fmt.Sprintf(":%s 349 alice #local :End of channel exception list\r\n", s.listener.Addr()), t)
	})

	t.Run("TestRPLINVITELIST", func(t *testing.T) {
		c1.Write([]byte("MODE #local +I abc\r\nMODE #local +I def\r\nMODE #local +I ghi\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		c1.Write([]byte("MODE #local +I\r\n"))
		abc, _ := r1.ReadBytes('\n')
		def, _ := r1.ReadBytes('\n')
		ghi, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')

		assertResponse(abc, fmt.Sprintf(":%s 346 alice #local abc\r\n", s.listener.Addr()), t)
		assertResponse(def, fmt.Sprintf(":%s 346 alice #local def\r\n", s.listener.Addr()), t)
		assertResponse(ghi, fmt.Sprintf(":%s 346 alice #local ghi\r\n", s.listener.Addr()), t)
		assertResponse(end, fmt.Sprintf(":%s 347 alice #local :End of channel invite list\r\n", s.listener.Addr()), t)
	})

	t.Run("TestRemoveModes", func(t *testing.T) {
		c1.Write([]byte("MODE #local -o bob\r\n"))
		c1.Write([]byte("MODE #local -k\r\n"))

		opRemoved, _ := r1.ReadBytes('\n')
		keyRemoved, _ := r1.ReadBytes('\n')
		assertResponse(opRemoved, fmt.Sprintf(":%s MODE -o bob\r\n", s.listener.Addr()), t)
		assertResponse(keyRemoved, fmt.Sprintf(":%s MODE -k\r\n", s.listener.Addr()), t)
	})
}

func TestWHO(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()

	t.Run("NoArgument", func(t *testing.T) {
		c1.Write([]byte("WHO\r\n"))
		resp, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 352 alice * alice %s %s alice H :0 Alice Smith\r\n", s.listener.Addr(), s.clients["alice"].Host, s.listener.Addr()), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice * :End of WHO list\r\n", s.listener.Addr()), t)
	})
}

func TestWHOIS(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, _ := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	bob := s.clients["bob"]

	c1.Write([]byte("WHOIS bob\r\n"))
	whois, _ := r1.ReadBytes('\n')
	server, _ := r1.ReadBytes('\n')
	idle, _ := r1.ReadBytes('\n')
	// TODO: check this when implemented
	// chans, _ := r1.ReadBytes('\n')
	assertResponse(whois, fmt.Sprintf(":%s 311 alice bob bob %s * :Bob Smith\r\n", s.listener.Addr(), bob.Host), t)
	assertResponse(server, fmt.Sprintf(":%s 312 alice bob %s :wip irc server\r\n", s.listener.Addr(), s.listener.Addr()), t)
	assertResponse(idle, fmt.Sprintf(":%s 317 alice bob %v %v :seconds idle, signon time\r\n", s.listener.Addr(), time.Since(bob.Idle).Round(time.Second).Seconds(), bob.JoinTime), t)
}

func TestChanFull(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #l\r\n"))
	c1.Write([]byte("MODE #l +l 0\r\n"))
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #l\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 471 bob #l :Cannot join channel (+l)\r\n", s.listener.Addr()), t)
}

func TestModerated(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #l\r\n"))
	c1.Write([]byte("MODE #l +m\r\n")) // add moderated
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #l\r\n"))
	c2.Write([]byte("PRIVMSG #l :hey\r\n"))
	r2.ReadBytes('\n')
	r2.ReadBytes('\n')
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 404 bob #l :Cannot send to channel\r\n", s.listener.Addr()), t)
}

func TestNoExternal(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #l\r\n"))
	c1.Write([]byte("MODE #l +n\r\n")) // add moderated
	r1.ReadBytes('\n')
	c2.Write([]byte("PRIVMSG #l :hey\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 404 bob #l :Cannot send to channel\r\n", s.listener.Addr()), t)
}

func TestInvite(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #local\r\n"))
	c1.Write([]byte("MODE #local +i\r\n"))
	c1.Write([]byte("MODE #local\r\n"))
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 473 bob #local :Cannot join channel (+i)\r\n", s.listener.Addr()), t)
}

func TestBan(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #local\r\n"))
	c1.Write([]byte("MODE #local +b bob!*@*\r\n")) // ban all nicks named bob
	c1.Write([]byte("MODE #local\r\n"))
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 474 bob #local :Cannot join channel (+b)\r\n", s.listener.Addr()), t)
}

func TestPRIVMSG(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()
	c1.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	r2.ReadBytes('\n')
	r2.ReadBytes('\n')
	r1.ReadBytes('\n')

	t.Run("TestClientPRIVMSG", func(t *testing.T) {
		// alice sends message to bob
		c1.Write([]byte("PRIVMSG bob :hello\r\n"))
		msgResp, _ := r2.ReadBytes('\n')
		assertResponse(msgResp, fmt.Sprintf(":%s PRIVMSG bob :hello\r\n", s.clients["alice"]), t)
	})
	t.Run("TestChannelPRIVMSG", func(t *testing.T) {
		// message sent to channel should broadcast to all members
		c1.Write([]byte("PRIVMSG #local :hello\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s PRIVMSG #local :hello\r\n", s.clients["alice"]), t)
	})
}

func TestAWAY(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()

	c1.Write([]byte("AWAY :I'm away\r\n"))
	nowAway, _ := r1.ReadBytes('\n')
	assertResponse(nowAway, fmt.Sprintf(":%s 306 alice :You have been marked as being away\r\n", s.listener.Addr()), t)

	c2.Write([]byte("PRIVMSG alice :Hey\r\n"))
	awayMsg, _ := r2.ReadBytes('\n')
	assertResponse(awayMsg, fmt.Sprintf(":%s 301 bob alice :I'm away\r\n", s.listener.Addr()), t)

	c1.Write([]byte("AWAY\r\n"))
	unAway, _ := r1.ReadBytes('\n')
	assertResponse(unAway, fmt.Sprintf(":%s 305 alice :You are no longer marked as being away\r\n", s.listener.Addr()), t)
}

func TestCaseInsensitivity(t *testing.T) {
	s, err := New(":6667")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()

	t.Run("TestNickCaseInsensitive", func(t *testing.T) {
		c1.Write([]byte("NICK BOB\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 433 alice BOB :Nickname is already in use\r\n", s.listener.Addr()), t)
		c1.Write([]byte("NICK boB\r\n"))
		resp, _ = r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 433 alice boB :Nickname is already in use\r\n", s.listener.Addr()), t)
	})

	t.Run("TestChanCaseInsensitive", func(t *testing.T) {
		c1.Write([]byte("JOIN #test\r\n"))
		r1.ReadBytes('\n')
		c2.Write([]byte("JOIN #tEsT\r\n"))
		r1.ReadBytes('\n')

		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s JOIN #test\r\n", s.clients["bob"]), t)
	})

	t.Run("TestCommandCaseInsensitive", func(t *testing.T) {
		c1.Write([]byte("who #test\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')

		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 315 alice #test :End of WHO list\r\n", s.listener.Addr()), t)
	})
}

// given a nick and a realname, return a connection that is already
// registered and a bufio.Reader that has already read past all the
// initial connection rigamarole (RPL's, MOTD, etc.)
func connectAndRegister(nick, realname string) (net.Conn, *bufio.Reader) {
	c, _ := net.Dial("tcp", ":6667")

	c.Write([]byte("NICK " + nick + "\r\n"))
	c.Write([]byte("USER " + nick + " 0 0 :" + realname + "\r\n"))

	r := bufio.NewReader(c)
	for i := 0; i < 13; i++ {
		r.ReadBytes('\n')
	}

	return c, r
}

func assertResponse(resp []byte, eq string, t *testing.T) {
	if string(resp) != eq {
		t.Error("expected", eq, "got", string(resp))
	}
}

func poll(s interface{}, eq interface{}) bool {
	c := make(chan bool)

	// start goroutine that continually checks pointer reference against
	// eq, and signals channel if true
	go func() {
		for {
			switch v := s.(type) {
			case *map[string]*client.Client:
				if len(*v) == eq {
					c <- true
					return
				}
			case *map[string]*channel.Member:
				if len(*v) == eq {
					c <- true
					return
				}
			case *map[string]*channel.Channel:
				if len(*v) == eq {
					c <- true
					return
				}
			}
		}
	}()

	// returns true if c returns a value before 500 miliseconds have elapsed
	select {
	case <-c:
		return true
	case <-time.After(time.Millisecond * 500):
		return false
	}
}
