package server

import (
	"bufio"
	"fmt"
	"net"
	"testing"

	"github.com/mitchr/gossip/channel"
	"golang.org/x/crypto/bcrypt"
)

var conf = &Config{Name: "gossip", Port: ":6667"}

func TestRegistration(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	conn, _ := connectAndRegister("alice", "Alice Smith")
	defer conn.Close()

	t.Run("NICKChange", func(t *testing.T) {
		conn, r := connectAndRegister("bob", "Bob Smith")
		defer conn.Close()

		conn.Write([]byte("NICK dan\r\n"))
		resp, _ := r.ReadBytes('\n')

		// sender should be the same user host, but with the previous nick
		assertResponse(resp, ":bob!bob@localhost NICK :dan\r\n", t)
	})
}

func TestOPER(t *testing.T) {
	conf2 := *conf
	pass, _ := bcrypt.GenerateFromPassword([]byte("adminpass"), bcrypt.MinCost)
	conf2.Ops = map[string][]byte{"admin": pass}
	s, err := New(&conf2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("a", "Alice")
	defer c.Close()

	t.Run("TestMissingParams", func(t *testing.T) {
		c.Write([]byte("OPER\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 461 a OPER :Not enough parameters\r\n", s.Name), t)
	})
	t.Run("TestIncorrectpassword", func(t *testing.T) {
		c.Write([]byte("OPER admin wrongPass\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 464 a :Password Incorrect\r\n", s.Name), t)
	})
	t.Run("TestCorrectpassword", func(t *testing.T) {
		c.Write([]byte("OPER admin adminpass\r\n"))
		operResp, _ := r.ReadBytes('\n')
		modeResp, _ := r.ReadBytes('\n')
		assertResponse(operResp, fmt.Sprintf(":%s 381 a :You are now an IRC operator\r\n", s.Name), t)
		assertResponse(modeResp, fmt.Sprintf(":%s MODE a +o\r\n", s.Name), t)
	})
}

// test cases are taken from https://www.irc.com/dev/docs/refs/commands/pass
func TestPASS(t *testing.T) {
	// need a special conf so we don't mess with the password for all the other tests
	conf2 := *conf
	pass, _ := bcrypt.GenerateFromPassword([]byte("letmein"), bcrypt.MinCost)
	conf2.Password = pass

	s, err := New(&conf2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	t.Run("TestRegisteredWithNoPASS", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))
		r := bufio.NewReader(c)
		resp, _ := r.ReadBytes('\n')
		err, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 464 chris :Password Incorrect\r\n", s.Name), t)
		assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.Name), t)
	})
	t.Run("TestPASSParamMissing", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("PASS\r\n"))

		r := bufio.NewReader(c)
		err, _ := r.ReadBytes('\n')
		// err, _ := r.ReadBytes('\n')

		assertResponse(err, fmt.Sprintf(":%s 461 * PASS :Not enough parameters\r\n", s.Name), t)
		// assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.Name), t)
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

		assertResponse(resp, fmt.Sprintf(":%s 464 chris :Password Incorrect\r\n", s.Name), t)
		assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.Name), t)
	})
	t.Run("TestPASSCorrect", func(t *testing.T) {
		c, _ := net.Dial("tcp", ":6667")
		defer c.Close()
		c.Write([]byte("PASS letmein\r\n"))
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))

		r := bufio.NewReader(c)
		for i := 0; i < 11; i++ {
			r.ReadBytes('\n')
		}

		t.Run("TestPASSAlreadyRegistered", func(t *testing.T) {
			c.Write([]byte("PASS letmein\r\n"))
			err, _ := r.ReadBytes('\n')
			assertResponse(err, fmt.Sprintf(":%s 462 chris :You may not reregister\r\n", s.Name), t)
		})
	})
}

func TestQUIT(t *testing.T) {
	s, err := New(conf)
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
	})

	t.Run("TestReasonInChannel", func(t *testing.T) {
		c1, r1 := connectAndRegister("bob", "Bob Smith")
		defer c1.Close()
		c2, r2 := connectAndRegister("dan", "Dan Jones")
		defer c2.Close()
		c1.Write([]byte("JOIN #l\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
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
	})
}

func TestChannelCreation(t *testing.T) {
	s, err := New(conf)
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
	joinResp, _ := r1.ReadBytes('\n')
	namreply, _ := r1.ReadBytes('\n')
	endNames, _ := r1.ReadBytes('\n')

	assertResponse(joinResp, ":alice!alice@localhost JOIN #local\r\n", t)
	assertResponse(namreply, fmt.Sprintf(":%s 353 alice = #local :~alice\r\n", s.Name), t)
	assertResponse(endNames, fmt.Sprintf(":%s 366 alice #local :End of /NAMES list\r\n", s.Name), t)

	t.Run("TestJoinNoParam", func(t *testing.T) {
		c1.Write([]byte("JOIN\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 461 alice JOIN :Not enough parameters\r\n", s.Name), t)
	})

	t.Run("TestJoinNonexistentChannelType", func(t *testing.T) {
		c1.Write([]byte("JOIN *testChan\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 403 alice *testChan :No such channel\r\n", s.Name), t)
	})

	t.Run("TestChanNameInsensitive", func(t *testing.T) {
		c2.Write([]byte("JOIN #LOcAl\r\n"))
		resp, _ := r2.ReadBytes('\n')
		r2.ReadBytes('\n')
		r1.ReadBytes('\n') // alice reading bob's join msg

		assertResponse(resp, ":bob!bob@localhost JOIN #local\r\n", t)
	})

	t.Run("TestChannelPART", func(t *testing.T) {
		// c1 leaves, c2 should receive a PARTing message from them
		c1.Write([]byte("PART #local :Goodbye\r\n"))
		aliceResp, _ := r1.ReadBytes('\n')
		bobResp, _ := r2.ReadBytes('\n')
		assertResponse(aliceResp, ":alice!alice@localhost PART #local :Goodbye\r\n", t)
		assertResponse(bobResp, ":alice!alice@localhost PART #local :Goodbye\r\n", t)
	})

	t.Run("TestChannelDestruction", func(t *testing.T) {
		c2.Write([]byte("PART #local\r\n"))
		response, _ := r2.ReadBytes('\n')
		assertResponse(response, ":bob!bob@localhost PART #local\r\n", t)
	})

	t.Run("TestJOIN0", func(t *testing.T) {
		c1.Write([]byte("JOIN #chan1\r\nJOIN #chan2\r\nJOIN #chan3\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')

		c1.Write([]byte("JOIN 0\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')

		c1.Write([]byte("LIST\r\n"))
		response, _ := r1.ReadBytes('\n')
		assertResponse(response, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.Name), t)
	})
}

func TestChannelKeys(t *testing.T) {
	s, err := New(conf)
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

	assertResponse(join1, ":alice!alice@localhost JOIN #1\r\n", t)
	assertResponse(join2, ":alice!alice@localhost JOIN #2\r\n", t)
	assertResponse(join3, ":alice!alice@localhost JOIN #3\r\n", t)

	t.Run("TestBadChannelKey", func(t *testing.T) {
		c2, r2 := connectAndRegister("dan", "Dan Smith")
		defer c2.Close()
		c2.Write([]byte("JOIN #1\r\n"))
		resp, _ := r2.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 475 dan #1 :Cannot join channel (+k)\r\n", s.Name), t)
	})
}

func TestTOPIC(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	c.Write([]byte("JOIN &test\r\n"))
	r.ReadBytes('\n')
	r.ReadBytes('\n')
	r.ReadBytes('\n')

	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :This is a test\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))

	unchanged, _ := r.ReadBytes('\n')
	assertResponse(unchanged, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.Name), t)
	changed, _ := r.ReadBytes('\n')
	assertResponse(changed, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.Name), t)
	retrieve, _ := r.ReadBytes('\n')
	assertResponse(retrieve, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.Name), t)

	r.ReadBytes('\n')
	clear, _ := r.ReadBytes('\n')
	assertResponse(clear, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.Name), t)

	t.Run("TestNoPrivileges", func(t *testing.T) {
		c2, r2 := connectAndRegister("b", "B")
		defer c2.Close()
		c2.Write([]byte("JOIN &test\r\nTOPIC &test :I have no privileges\r\n"))
		r2.ReadBytes('\n')
		r2.ReadBytes('\n')
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 482 b &test :You're not a channel operator\r\n", s.Name), t)
	})
}

func TestKICK(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	r1.ReadBytes('\n')
	r2.ReadBytes('\n')
	r2.ReadBytes('\n')
	c1.Write([]byte("KICK #local bob\r\n"))
	aliceKick, _ := r1.ReadBytes('\n')
	bobKick, _ := r2.ReadBytes('\n')

	// check received correct response
	assertResponse(aliceKick, ":alice!alice@localhost KICK #local bob :alice\r\n", t)
	assertResponse(bobKick, ":alice!alice@localhost KICK #local bob :alice\r\n", t)
}

func TestNAMES(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice", "Alice Smith")
	defer c.Close()

	c.Write([]byte("JOIN &test\r\n"))
	r.ReadBytes('\n')
	r.ReadBytes('\n')
	r.ReadBytes('\n')
	c.Write([]byte("NAMES &test\r\n"))
	namreply, _ := r.ReadBytes('\n')
	end, _ := r.ReadBytes('\n')

	assertResponse(namreply, fmt.Sprintf(":%s 353 alice = &test :~alice\r\n", s.Name), t)
	assertResponse(end, fmt.Sprintf(":%s 366 alice &test :End of /NAMES list\r\n", s.Name), t)
}

func TestLIST(t *testing.T) {
	s, err := New(conf)
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
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		c.Write([]byte("LIST\r\n"))
		listReply, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')

		assertResponse(listReply, fmt.Sprintf(":%s 322 alice &test 1 :\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.Name), t)
	})

	t.Run("TestParam", func(t *testing.T) {
		c.Write([]byte("JOIN &params\r\n"))
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		r.ReadBytes('\n')
		c.Write([]byte("LIST &params\r\n"))
		listReply, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')

		assertResponse(listReply, fmt.Sprintf(":%s 322 alice &params 1 :\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.Name), t)
	})
}

func TestMODE(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')

	t.Run("TestUserNotInChan", func(t *testing.T) {
		c2.Write([]byte("MODE #local +o bob\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 441 bob bob #local :They aren't on that channel\r\n", s.Name), t)
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

	assertResponse(passApplied, fmt.Sprintf(":%s MODE +k pass\r\n", s.Name), t)
	assertResponse(opApplied, fmt.Sprintf(":%s MODE +o bob\r\n", s.Name), t)
	assertResponse(getModeResp, fmt.Sprintf(":%s 324 alice #local k\r\n", s.Name), t)

	if s.channels["#local"].Members["bob"].Prefix != "@" {
		t.Error("Failed to set member mode")
	}

	t.Run("TestChannelModeMissingParam", func(t *testing.T) {
		c1.Write([]byte("MODE #local +l\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 461 alice :+l :Not enough parameters\r\n", s.Name), t)
	})

	t.Run("TestUserModeMissingParam", func(t *testing.T) {
		c1.Write([]byte("MODE #local +o\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 461 alice :+o :Not enough parameters\r\n", s.Name), t)
	})

	t.Run("TestUnknownMode", func(t *testing.T) {
		c1.Write([]byte("MODE #local +w\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 472 alice w :is unknown mode char to me for #local\r\n", s.Name), t)
	})

	t.Run("TestRPLBANLIST", func(t *testing.T) {
		s.clients["alice"].FillGrants()

		c1.Write([]byte("MODE #local +b abc\r\nMODE #local +b def\r\nMODE #local +b ghi\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		c1.Write([]byte("MODE #local +b\r\n"))
		abc, _ := r1.ReadBytes('\n')
		def, _ := r1.ReadBytes('\n')
		ghi, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')

		assertResponse(abc, fmt.Sprintf(":%s 367 alice #local abc\r\n", s.Name), t)
		assertResponse(def, fmt.Sprintf(":%s 367 alice #local def\r\n", s.Name), t)
		assertResponse(ghi, fmt.Sprintf(":%s 367 alice #local ghi\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 368 alice #local :End of channel ban list\r\n", s.Name), t)

		// test that 'MODE #local b' works
		c1.Write([]byte("MODE #local b\r\n"))
		abc, _ = r1.ReadBytes('\n')
		def, _ = r1.ReadBytes('\n')
		ghi, _ = r1.ReadBytes('\n')
		end, _ = r1.ReadBytes('\n')
		assertResponse(abc, fmt.Sprintf(":%s 367 alice #local abc\r\n", s.Name), t)
		assertResponse(def, fmt.Sprintf(":%s 367 alice #local def\r\n", s.Name), t)
		assertResponse(ghi, fmt.Sprintf(":%s 367 alice #local ghi\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 368 alice #local :End of channel ban list\r\n", s.Name), t)
	})

	t.Run("TestRPLEXCEPTLIST", func(t *testing.T) {
		s.clients["alice"].FillGrants()

		c1.Write([]byte("MODE #local +e abc\r\nMODE #local +e def\r\nMODE #local +e ghi\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		c1.Write([]byte("MODE #local +e\r\n"))
		abc, _ := r1.ReadBytes('\n')
		def, _ := r1.ReadBytes('\n')
		ghi, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')

		assertResponse(abc, fmt.Sprintf(":%s 348 alice #local abc\r\n", s.Name), t)
		assertResponse(def, fmt.Sprintf(":%s 348 alice #local def\r\n", s.Name), t)
		assertResponse(ghi, fmt.Sprintf(":%s 348 alice #local ghi\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 349 alice #local :End of channel exception list\r\n", s.Name), t)
	})

	t.Run("TestRPLINVITELIST", func(t *testing.T) {
		s.clients["alice"].FillGrants()

		c1.Write([]byte("MODE #local +I abc\r\nMODE #local +I def\r\nMODE #local +I ghi\r\n"))
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		c1.Write([]byte("MODE #local +I\r\n"))
		abc, _ := r1.ReadBytes('\n')
		def, _ := r1.ReadBytes('\n')
		ghi, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')

		assertResponse(abc, fmt.Sprintf(":%s 346 alice #local abc\r\n", s.Name), t)
		assertResponse(def, fmt.Sprintf(":%s 346 alice #local def\r\n", s.Name), t)
		assertResponse(ghi, fmt.Sprintf(":%s 346 alice #local ghi\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 347 alice #local :End of channel invite list\r\n", s.Name), t)
	})

	t.Run("TestRemoveModes", func(t *testing.T) {
		c1.Write([]byte("MODE #local -o bob\r\n"))
		c1.Write([]byte("MODE #local -k\r\n"))

		opRemoved, _ := r1.ReadBytes('\n')
		keyRemoved, _ := r1.ReadBytes('\n')
		assertResponse(opRemoved, fmt.Sprintf(":%s MODE -o bob\r\n", s.Name), t)
		assertResponse(keyRemoved, fmt.Sprintf(":%s MODE -k\r\n", s.Name), t)
	})
}

func TestWHO(t *testing.T) {
	s, err := New(conf)
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
		assertResponse(resp, fmt.Sprintf(":%s 352 alice * alice localhost %s alice H :0 Alice Smith\r\n", s.Name, s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice * :End of WHO list\r\n", s.Name), t)
	})
}

func TestWHOIS(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice", "Alice Smith")
	defer c1.Close()
	c2, _ := connectAndRegister("bob", "Bob Smith")
	defer c2.Close()

	c1.Write([]byte("WHOIS bob\r\n"))
	whois, _ := r1.ReadBytes('\n')
	server, _ := r1.ReadBytes('\n')
	r1.ReadBytes('\n') // TODO: check bob idle and join time
	chans, _ := r1.ReadBytes('\n')
	end, _ := r1.ReadBytes('\n')

	assertResponse(whois, fmt.Sprintf(":%s 311 alice bob bob %s * :Bob Smith\r\n", s.Name, "localhost"), t)
	assertResponse(server, fmt.Sprintf(":%s 312 alice bob %s :wip irc server\r\n", s.Name, s.Name), t)
	// assertResponse(idle, fmt.Sprintf(":%s 317 alice bob %v %v :seconds idle, signon time\r\n", s.Name, time.Since(bob.Idle).Round(time.Second).Seconds(), bob.JoinTime), t)
	assertResponse(chans, fmt.Sprintf(":%s 319 alice bob\r\n", s.Name), t)
	assertResponse(end, fmt.Sprintf(":%s 318 alice :End of /WHOIS list\r\n", s.Name), t)
}

func TestChanFull(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #l\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 471 bob #l :Cannot join channel (+l)\r\n", s.Name), t)
}

func TestModerated(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #l\r\n"))
	c2.Write([]byte("PRIVMSG #l :hey\r\n"))
	r1.ReadBytes('\n')
	r2.ReadBytes('\n')
	r2.ReadBytes('\n')
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 404 bob #l :Cannot send to channel\r\n", s.Name), t)
}

func TestNoExternal(t *testing.T) {
	s, err := New(conf)
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
	c1.Write([]byte("MODE #l +n\r\n"))
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("PRIVMSG #l :hey\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 404 bob #l :Cannot send to channel\r\n", s.Name), t)
}

func TestInvite(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 473 bob #local :Cannot join channel (+i)\r\n", s.Name), t)
}

func TestBan(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	resp, _ := r2.ReadBytes('\n')

	assertResponse(resp, fmt.Sprintf(":%s 474 bob #local :Cannot join channel (+b)\r\n", s.Name), t)
}

func TestPRIVMSG(t *testing.T) {
	s, err := New(conf)
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
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	c2.Write([]byte("JOIN #local\r\n"))
	r2.ReadBytes('\n')
	r2.ReadBytes('\n')
	r1.ReadBytes('\n')

	t.Run("TestClientPRIVMSG", func(t *testing.T) {
		// alice sends message to bob
		c1.Write([]byte("PRIVMSG bob :hello\r\n"))
		msgResp, _ := r2.ReadBytes('\n')
		assertResponse(msgResp, ":alice!alice@localhost PRIVMSG bob :hello\r\n", t)
	})
	t.Run("TestChannelPRIVMSG", func(t *testing.T) {
		// message sent to channel should broadcast to all members
		c1.Write([]byte("PRIVMSG #local :hello\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, ":alice!alice@localhost PRIVMSG #local :hello\r\n", t)
	})
	t.Run("TestMultipleTargets", func(t *testing.T) {
		c3, r3 := connectAndRegister("c", "c")
		defer c3.Close()
		c3.Write([]byte("JOIN #local\r\n"))
		// skip joinmsgs
		r1.ReadBytes('\n')
		r2.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n') // namereply
		c3.Write([]byte("PRIVMSG #local,bob :From c\r\n"))
		chanResp1, _ := r1.ReadBytes('\n')
		chanResp2, _ := r2.ReadBytes('\n')
		privmsgResp, _ := r2.ReadBytes('\n')
		assertResponse(chanResp1, ":c!c@localhost PRIVMSG #local :From c\r\n", t)
		assertResponse(chanResp2, ":c!c@localhost PRIVMSG #local :From c\r\n", t)
		assertResponse(privmsgResp, ":c!c@localhost PRIVMSG bob :From c\r\n", t)
	})
}

func TestAWAY(t *testing.T) {
	s, err := New(conf)
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
	assertResponse(nowAway, fmt.Sprintf(":%s 306 alice :You have been marked as being away\r\n", s.Name), t)

	c2.Write([]byte("PRIVMSG alice :Hey\r\n"))
	awayMsg, _ := r2.ReadBytes('\n')
	assertResponse(awayMsg, fmt.Sprintf(":%s 301 bob alice :I'm away\r\n", s.Name), t)

	c1.Write([]byte("AWAY\r\n"))
	unAway, _ := r1.ReadBytes('\n')
	assertResponse(unAway, fmt.Sprintf(":%s 305 alice :You are no longer marked as being away\r\n", s.Name), t)
}
