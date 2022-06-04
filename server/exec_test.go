package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mitchr/gossip/channel"
	"github.com/mitchr/gossip/client"
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

	t.Run("UnregisteredCommands", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("WALLOPS\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 451 * :You have not registered\r\n", t)
	})

	t.Run("NICKMissing", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("NICK\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 431 * :No nickname given\r\n", t)
	})

	t.Run("ErroneousNick", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("NICK *\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 432 * :Erroneous nickname\r\n", t)
	})

	t.Run("NICKChange", func(t *testing.T) {
		c1, r1 := connectAndRegister("bob")
		defer c1.Close()

		c2, r2 := connectAndRegister("c")
		defer c2.Close()

		bob, _ := s.getClient("bob")
		c, _ := s.getClient("c")
		ch := channel.New("local", channel.Remote)
		ch.SetMember(&channel.Member{Client: bob})
		ch.SetMember(&channel.Member{Client: c})
		s.setChannel(ch)

		c1.Write([]byte("NICK dan\r\n"))
		resp, _ := r1.ReadBytes('\n')
		cAck, _ := r2.ReadBytes('\n')

		// sender should be the same user host, but with the previous nick
		assertResponse(resp, ":bob!bob@localhost NICK :dan\r\n", t)
		assertResponse(cAck, ":bob!bob@localhost NICK :dan\r\n", t)
	})

	t.Run("TestUserWhenRegistered", func(t *testing.T) {
		conn, r := connectAndRegister("alice")
		defer conn.Close()

		conn.Write([]byte("USER dan\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 462 alice :You may not reregister\r\n", t)
	})

	t.Run("TestUserMissingParams", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("USER\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 * USER :Not enough parameters\r\n", t)
	})

	t.Run("TestUserMissingParams2", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("USER username * * :\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 * USER :Not enough parameters\r\n", t)
	})

	// should not get back a failure numeric when changing nick to itself
	t.Run("TestNickSame", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("CAP LS 302\r\nNICK foo\r\nUSER u s e r\r\nNICK foo\r\nCAP END\r\n"))

		r.ReadBytes('\n') // read CAP LS response
		resp, _ := r.ReadBytes('\n')

		foo, _ := s.getClient("foo")
		assertResponse(resp, fmt.Sprintf(RPL_WELCOME+"\r\n", s.Name, foo.Nick, s.Network, foo), t)
	})

	t.Run("TestNickCaseChange", func(t *testing.T) {
		conn, r := connectAndRegister("carl")
		defer conn.Close()

		carl, _ := s.getClient("carl")
		prefixBeforeChange := carl.String()

		conn.Write([]byte("NICK Carl\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s NICK :Carl\r\n", prefixBeforeChange), t)
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

	c, r := connectAndRegister("a")
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
	t.Run("TestCorrectPassword", func(t *testing.T) {
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
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))
		resp, _ := r.ReadBytes('\n')
		err, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 464 chris :Password Incorrect\r\n", s.Name), t)
		assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.Name), t)
	})
	t.Run("TestPASSParamMissing", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("PASS\r\n"))
		err, _ := r.ReadBytes('\n')
		// err, _ := r.ReadBytes('\n')

		assertResponse(err, fmt.Sprintf(":%s 461 * PASS :Not enough parameters\r\n", s.Name), t)
		// assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.Name), t)
	})
	t.Run("TestPASSIncorrect", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("PASS opensesame\r\n"))
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))
		resp, _ := r.ReadBytes('\n')
		err, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 464 chris :Password Incorrect\r\n", s.Name), t)
		assertResponse(err, fmt.Sprintf("ERROR :Closing Link: %s (Bad Password)\r\n", s.Name), t)
	})
	t.Run("TestPASSCorrect", func(t *testing.T) {
		c, r, p := connect(s)
		defer p()

		c.Write([]byte("PASS letmein\r\n"))
		c.Write([]byte("NICK chris\r\n"))
		c.Write([]byte("USER c 0 * :Chrisa!\r\n"))

		for i := 0; i < 13; i++ {
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
		c, r := connectAndRegister("alice")
		defer c.Close()
		c.Write([]byte("QUIT\r\n"))

		quitResp, _ := r.ReadBytes('\n')
		assertResponse(quitResp, "ERROR :alice quit\r\n", t)
	})

	t.Run("TestReasonInChannel", func(t *testing.T) {
		c1, r1 := connectAndRegister("bob")
		defer c1.Close()
		c2, r2 := connectAndRegister("dan")
		defer c2.Close()

		s.channels["#l"] = channel.New("l", '#')
		s.channels["#l"].SetMember(&channel.Member{Client: s.clients["bob"], Prefix: string(channel.Operator)})
		s.channels["#l"].SetMember(&channel.Member{Client: s.clients["dan"]})

		bob, _ := s.getClient("bob")

		c1.Write([]byte("QUIT :Done for the day\r\n"))

		bobQuitErr, _ := r1.ReadBytes('\n')
		assertResponse(bobQuitErr, "ERROR :Done for the day\r\n", t)

		danReceivesReason, _ := r2.ReadBytes('\n')
		assertResponse(danReceivesReason, fmt.Sprintf(":%s QUIT :Done for the day\r\n", bob.String()), t)
	})
}

func TestSETNAME(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
	defer c.Close()

	t.Run("EmptyRealname", func(t *testing.T) {
		c.Write([]byte("SETNAME\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, "FAIL SETNAME INVALID_REALNAME :Realname cannot be empty\r\n", t)
	})

	t.Run("Success", func(t *testing.T) {
		c.Write([]byte("CAP REQ setname\r\nSETNAME :myName\r\n"))
		r.ReadBytes('\n')
		resp, _ := r.ReadBytes('\n')

		alice, _ := s.getClient("alice")
		assertResponse(resp, fmt.Sprintf(":%s SETNAME :myName\r\n", alice), t)
		if alice.Realname != "myName" {
			t.Error("did not change real name")
		}
	})

	t.Run("ChannelNotify", func(t *testing.T) {
		c2, r2 := connectAndRegister("bob")
		defer c2.Close()

		local := channel.New("local", channel.Remote)
		alice, _ := s.getClient("alice")
		bob, _ := s.getClient("bob")
		local.SetMember(&channel.Member{Client: alice, Prefix: string(channel.Operator)})
		local.SetMember(&channel.Member{Client: bob})
		s.setChannel(local)

		c2.Write([]byte("CAP REQ setname\r\nSETNAME :bobSmith\r\n"))
		r2.ReadBytes('\n')
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s SETNAME :bobSmith\r\n", bob), t)

		bobsChange, _ := r.ReadBytes('\n')
		assertResponse(bobsChange, fmt.Sprintf(":%s SETNAME :bobSmith\r\n", bob), t)
	})
}

func TestCHGHOST(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
	defer c.Close()

	t.Run("NotEnoughParams", func(t *testing.T) {
		c.Write([]byte("CHGHOST\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(ERR_NEEDMOREPARAMS+"\r\n", s.Name, "alice", "CHGHOST"), t)
	})

	t.Run("Success", func(t *testing.T) {
		alice, _ := s.getClient("alice")
		oldPrefix := alice.String()

		c.Write([]byte("CAP REQ chghost\r\nCHGHOST newUser newHost\r\n"))
		r.ReadBytes('\n')
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s CHGHOST newUser newHost\r\n", oldPrefix), t)
		if alice.User != "newUser" {
			t.Error("did not change user")
		}
		if alice.Host != "newHost" {
			t.Error("did not change host")
		}
	})

	t.Run("ChannelNotifyNoCapSupported", func(t *testing.T) {
		c2, r2 := connectAndRegister("bob")
		defer c2.Close()

		local := channel.New("local", channel.Remote)
		alice, _ := s.getClient("alice")
		bob, _ := s.getClient("bob")
		local.SetMember(&channel.Member{Client: alice, Prefix: string(channel.Operator)})
		local.SetMember(&channel.Member{Client: bob})
		s.setChannel(local)

		oldPrefix := alice.String()
		c.Write([]byte("CHGHOST user1 host1\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s CHGHOST user1 host1\r\n", oldPrefix), t)

		quit, _ := r2.ReadBytes('\n')
		join, _ := r2.ReadBytes('\n')
		modes, _ := r2.ReadBytes('\n')
		assertResponse(quit, fmt.Sprintf(":%s QUIT :Changing hostname\r\n", oldPrefix), t)
		assertResponse(join, fmt.Sprintf(":%s JOIN #local\r\n", alice), t)
		assertResponse(modes, fmt.Sprintf(":%s MODE #local +o alice\r\n", s.Name), t)
	})
}

func TestChannelCreation(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
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

	t.Run("TestCreateChanSameTime", func(t *testing.T) {
		c3, r3 := connectAndRegister("race1")
		c4, r4 := connectAndRegister("race2")
		defer c3.Close()
		defer c4.Close()

		c3.Write([]byte("JOIN #race\r\nPING 10\r\n"))
		c4.Write([]byte("JOIN #race\r\nPING 11\r\n"))
		readUntilPONG(r3)
		readUntilPONG(r4)

		race, _ := s.getChannel("#race")
		race1, _ := race.GetMember("race1")
		race2, _ := race.GetMember("race2")

		if ((race1 == nil && race2 != nil) || (race1 != nil && race2 == nil)) || (race1.Is(channel.Founder) && race2.Is(channel.Founder)) {
			t.Error("join at same time caused double founder")
		}
	})

	t.Run("TestChanNameInsensitive", func(t *testing.T) {
		c2.Write([]byte("JOIN #LOcAl\r\n"))
		resp, _ := r2.ReadBytes('\n')
		r2.ReadBytes('\n')
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
		c3, r3 := connectAndRegister("c")
		c3.Write([]byte("JOIN #chan1\r\nJOIN #chan2\r\nJOIN #chan3\r\n"))
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')

		c3.Write([]byte("JOIN 0\r\n"))
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')
		r3.ReadBytes('\n')

		c3.Write([]byte("LIST\r\n"))
		response, _ := r3.ReadBytes('\n')
		assertResponse(response, fmt.Sprintf(":%s 323 c :End of /LIST\r\n", s.Name), t)
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

	c, r := connectAndRegister("alice")
	defer c.Close()

	c.Write([]byte("JOIN #1,#2,#3 Key1,Key2\r\n"))
	join1, _ := r.ReadBytes('\n')
	r.ReadBytes('\n') // skip namreply
	r.ReadBytes('\n')
	join2, _ := r.ReadBytes('\n')
	r.ReadBytes('\n')
	r.ReadBytes('\n')
	join3, _ := r.ReadBytes('\n')

	assertResponse(join1, ":alice!alice@localhost JOIN #1\r\n", t)
	assertResponse(join2, ":alice!alice@localhost JOIN #2\r\n", t)
	assertResponse(join3, ":alice!alice@localhost JOIN #3\r\n", t)

	t.Run("TestBadChannelKey", func(t *testing.T) {
		c2, r2 := connectAndRegister("dan")
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

	c, r := connectAndRegister("alice")
	defer c.Close()

	s.channels["&test"] = channel.New("test", '&')
	s.channels["&test"].SetMember(&channel.Member{Client: s.clients["alice"], Prefix: string(channel.Operator)})

	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :This is a test\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))
	c.Write([]byte("TOPIC &test :\r\n"))
	c.Write([]byte("TOPIC &test\r\n"))

	unchanged, _ := r.ReadBytes('\n')
	assertResponse(unchanged, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.Name), t)
	changed, _ := r.ReadBytes('\n')
	assertResponse(changed, fmt.Sprintf(":%s TOPIC &test :This is a test\r\n", s.Name), t)
	retrieve, _ := r.ReadBytes('\n')
	assertResponse(retrieve, fmt.Sprintf(":%s 332 alice &test :This is a test\r\n", s.Name), t)
	r.ReadBytes('\n')
	// TODO: figure out a way to check the unix timestamp
	// topicWhoTime, _ := r.ReadBytes('\n')
	// assertResponse(topicWhoTime, fmt.Sprintf(RPL_TOPICWHOTIME+"\r\n", s.Name, "alice", "&test", "alice", 0), t)

	r.ReadBytes('\n')
	clear, _ := r.ReadBytes('\n')
	assertResponse(clear, fmt.Sprintf(":%s 331 alice &test :No topic is set\r\n", s.Name), t)

	t.Run("MissingParam", func(t *testing.T) {
		c.Write([]byte("TOPIC\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 alice TOPIC :Not enough parameters\r\n", t)
	})

	t.Run("TestNoPrivilegesProtectedChan", func(t *testing.T) {
		testChan, _ := s.getChannel("&test")
		testChan.Protected = true

		c2, r2 := connectAndRegister("b")
		defer c2.Close()
		c2.Write([]byte("JOIN &test\r\nTOPIC &test :I have no privileges\r\n"))
		r2.ReadBytes('\n')
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

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	local := channel.New("local", '#')
	s.setChannel(local)
	local.SetMember(&channel.Member{Client: s.clients["alice"], Prefix: string(channel.Operator)})
	local.SetMember(&channel.Member{Client: s.clients["bob"]})
	c1.Write([]byte("KICK #local bob\r\n"))

	// check received correct response
	bobKick, _ := r2.ReadBytes('\n')
	assertResponse(bobKick, ":alice!alice@localhost KICK #local bob :alice\r\n", t)

	t.Run("MissingParam", func(t *testing.T) {
		c1.Write([]byte("KICK\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 alice KICK :Not enough parameters\r\n", t)
	})

	t.Run("KICKMoreChansThanUsers", func(t *testing.T) {
		c1.Write([]byte("KICK #test,#test1 bob\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 alice KICK :Not enough parameters\r\n", t)
	})

	t.Run("NoSuchChannel", func(t *testing.T) {
		testChannel := channel.New("test", channel.Remote)
		testChannel.SetMember(&channel.Member{Client: s.clients["bob"]})
		s.setChannel(testChannel)
		c1.Write([]byte("KICK #test bob\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 442 alice #test :You're not on that channel\r\n", t)
	})

	t.Run("NoPrivileges", func(t *testing.T) {
		s.channels["#test"].SetMember(&channel.Member{Client: s.clients["alice"]})
		c1.Write([]byte("KICK #test bob\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 482 alice #test :You're not a channel operator\r\n", t)
	})

	t.Run("NotOnChannel", func(t *testing.T) {
		c1.Write([]byte("KICK #notrealchan bob\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 403 alice #notrealchan :No such channel\r\n", t)
	})

	t.Run("KickClientNotInChannel", func(t *testing.T) {
		c1.Write([]byte("KICK #local unknownUser\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 441 alice unknownUser #local :They aren't on that channel\r\n", s.Name), t)
	})
}

func TestNAMES(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
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

	t.Run("TestNoParam", func(t *testing.T) {
		c.Write([]byte("NAMES\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 366 alice * :End of /NAMES list\r\n", s.Name), t)
	})

	t.Run("TestUnknownChan", func(t *testing.T) {
		c.Write([]byte("NAMES #notReal\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 366 alice #notReal :End of /NAMES list\r\n", s.Name), t)
	})

	t.Run("TestSecretChanNotBelong", func(t *testing.T) {
		secret := channel.New("secret", channel.Remote)
		secret.Secret = true
		s.setChannel(secret)

		c.Write([]byte("NAMES #secret\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 366 alice #secret :End of /NAMES list\r\n", s.Name), t)
	})

	t.Run("TestSecretChanBelong", func(t *testing.T) {
		secret, _ := s.getChannel("#secret")
		alice, _ := s.getClient("alice")
		secret.SetMember(&channel.Member{Client: alice})

		c.Write([]byte("NAMES #secret\r\n"))
		namreply, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')
		assertResponse(namreply, fmt.Sprintf(":%s 353 alice @ #secret :alice\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 366 alice #secret :End of /NAMES list\r\n", s.Name), t)
	})
}

func TestLIST(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
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

	// if a client is a member of a secret channel, they should get an RPL_LIST reply for it
	t.Run("TestSecretBelongs", func(t *testing.T) {
		params, _ := s.getChannel("&params")
		params.Secret = true

		c.Write([]byte("LIST &params\r\n"))
		listReply, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')
		assertResponse(listReply, fmt.Sprintf(":%s 322 alice &params 1 :\r\n", s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.Name), t)
	})

	t.Run("TestSecretNotBelongs", func(t *testing.T) {
		params, _ := s.getChannel("&params")
		params.DeleteMember("alice")

		c.Write([]byte("LIST &params\r\n"))
		end, _ := r.ReadBytes('\n')
		assertResponse(end, fmt.Sprintf(":%s 323 alice :End of /LIST\r\n", s.Name), t)
	})
}

func TestMOTD(t *testing.T) {
	confCopy := *conf
	s, err := New(&confCopy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
	defer c.Close()

	t.Run("NoFile", func(t *testing.T) {
		c.Write([]byte("MOTD\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(ERR_NOMOTD+"\r\n", s.Name, "alice"), t)
	})

	t.Run("Success", func(t *testing.T) {
		s.motd = []string{"this is line 1", "line 2"}
		c.Write([]byte("MOTD\r\n"))
		start, _ := r.ReadBytes('\n')
		line1, _ := r.ReadBytes('\n')
		line2, _ := r.ReadBytes('\n')
		end, _ := r.ReadBytes('\n')

		assertResponse(start, fmt.Sprintf(RPL_MOTDSTART+"\r\n", s.Name, "alice", s.Name), t)
		assertResponse(line1, fmt.Sprintf(RPL_MOTD+"\r\n", s.Name, "alice", "this is line 1"), t)
		assertResponse(line2, fmt.Sprintf(RPL_MOTD+"\r\n", s.Name, "alice", "line 2"), t)
		assertResponse(end, fmt.Sprintf(RPL_ENDOFMOTD+"\r\n", s.Name, "alice"), t)
	})
}

func TestMODEChannel(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	local := channel.New("local", '#')
	s.setChannel(local)
	local.SetMember(&channel.Member{Client: s.clients["alice"]})

	t.Run("TestUserNotInChan", func(t *testing.T) {
		c2.Write([]byte("MODE #local +o bob\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 441 bob bob #local :They aren't on that channel\r\n", s.Name), t)
	})

	bob := &channel.Member{Client: s.clients["bob"]}
	local.SetMember(bob)

	c1.Write([]byte("MODE #local +k pass\r\n"))
	c1.Write([]byte("MODE #local +o bob\r\n"))
	c1.Write([]byte("MODE #local\r\n"))
	passApplied, _ := r1.ReadBytes('\n')
	opApplied, _ := r1.ReadBytes('\n')
	getModeResp, _ := r1.ReadBytes('\n')

	assertResponse(passApplied, fmt.Sprintf(":%s MODE #local +k pass\r\n", s.Name), t)
	assertResponse(opApplied, fmt.Sprintf(":%s MODE #local +o bob\r\n", s.Name), t)
	assertResponse(getModeResp, fmt.Sprintf(":%s 324 alice #local k\r\n", s.Name), t)

	if bob.Prefix != "@" {
		t.Error("Failed to set member mode")
	}

	t.Run("TestUnknownChannel", func(t *testing.T) {
		c1.Write([]byte("MODE #notExist +w\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 403 alice #notExist :No such channel\r\n", s.Name), t)
	})

	t.Run("TestChannelModeMissingParam", func(t *testing.T) {
		c1.Write([]byte("MODE #local +l\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 461 alice :+l :Not enough parameters\r\n", s.Name), t)
	})

	t.Run("TestUnknownMode", func(t *testing.T) {
		c1.Write([]byte("MODE #local +w\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 472 alice w :is unknown mode char to me for #local\r\n", s.Name), t)
	})

	t.Run("TestIllFormedKey", func(t *testing.T) {
		c1.Write([]byte("MODE #local +k :ill-formed key\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 525 alice #local :Key is not well-formed\r\n", s.Name), t)
	})

	t.Run("TestEmptyKey", func(t *testing.T) {
		c1.Write([]byte("MODE #local +k :\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 525 alice #local :Key is not well-formed\r\n", s.Name), t)
	})

	t.Run("TestTooLongKey", func(t *testing.T) {
		c1.Write([]byte("MODE #local +k 123456789012345678901234\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 525 alice #local :Key is not well-formed\r\n", s.Name), t)
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
		assertResponse(opRemoved, fmt.Sprintf(":%s MODE #local -o bob\r\n", s.Name), t)
		assertResponse(keyRemoved, fmt.Sprintf(":%s MODE #local -k\r\n", s.Name), t)
	})
}

func TestMODEClient(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("alice")
	defer c.Close()

	alice, _ := s.getClient("alice")

	t.Run("TestModeNoParam", func(t *testing.T) {
		c.Write([]byte("MODE\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 221 alice r\r\n", s.Name), t)
	})

	t.Run("TestUnknownNick", func(t *testing.T) {
		c.Write([]byte("MODE bob +o\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 401 alice bob :No such nick/channel\r\n", s.Name), t)
	})

	t.Run("TestModifyOtherUser", func(t *testing.T) {
		d, _ := connectAndRegister("bob")
		defer d.Close()

		c.Write([]byte("MODE bob +o\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 502 alice :Can't change mode for other users\r\n", s.Name), t)
	})

	t.Run("TestUnknownMode", func(t *testing.T) {
		c.Write([]byte("MODE alice +j\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 501 alice :Unknown MODE flag\r\n", s.Name), t)
		r.ReadBytes('\n')
	})

	t.Run("TestOwnModeEcho", func(t *testing.T) {
		c.Write([]byte("MODE alice\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 221 alice r\r\n", s.Name), t)
	})

	t.Run("TestAddMode", func(t *testing.T) {
		c.Write([]byte("MODE alice +w\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s MODE alice +w\r\n", s.Name), t)

		if !alice.Is(client.Wallops) {
			t.Error(alice.Mode)
		}
	})

	t.Run("TestRemoveMode", func(t *testing.T) {
		c.Write([]byte("MODE alice -w\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s MODE alice -w\r\n", s.Name), t)

		if alice.Is(client.Wallops) {
			t.Error(alice.Mode)
		}
	})

	t.Run("TestAddMultipleMode", func(t *testing.T) {
		c.Write([]byte("MODE alice +wi\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s MODE alice +w+i\r\n", s.Name), t)

		if !alice.Is(client.Wallops) || !alice.Is(client.Invisible) {
			t.Error(alice.Mode)
		}
	})

	t.Run("TestRemoveMultipleMode", func(t *testing.T) {
		c.Write([]byte("MODE alice -wi\r\n"))
		resp, _ := r.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s MODE alice -w-i\r\n", s.Name), t)

		if alice.Is(client.Wallops) || alice.Is(client.Invisible) {
			t.Error(alice.Mode)
		}
	})
}

func TestWHOClient(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()

	t.Run("NoArgument", func(t *testing.T) {
		c1.Write([]byte("WHO\r\n"))
		resp, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 352 alice * alice localhost %s alice H :0 alice\r\n", s.Name, s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice * :End of WHO list\r\n", s.Name), t)
	})

	t.Run("TestAwayOp", func(t *testing.T) {
		alice, _ := s.getClient("alice")
		alice.Mode |= client.Away | client.Op

		c1.Write([]byte("WHO\r\n"))
		resp, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 352 alice * alice localhost %s alice G* :0 alice\r\n", s.Name, s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice * :End of WHO list\r\n", s.Name), t)
	})

	t.Run("WHObob", func(t *testing.T) {
		c2, _ := connectAndRegister("bob")
		defer c2.Close()

		c1.Write([]byte("WHO bob\r\n"))
		resp, _ := r1.ReadBytes('\n')
		r1.ReadBytes('\n') // end
		assertResponse(resp, fmt.Sprintf(":%s 352 alice * bob localhost %s bob H :0 bob\r\n", s.Name, s.Name), t)
	})
}

func TestWHOXClient(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, _ := connectAndRegister("bob")
	defer c2.Close()

	c1.Write([]byte("WHO bob %%tcuihsnfdlaor,10\r\n"))
	resp, _ := r1.ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(":%s 354 alice 10 * bob 127.0.0.1 localhost gossip bob H 0 0 0 n/a :bob\r\n", s.Name), t)
}

func TestWHOChannel(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()

	local := channel.New("local", channel.Remote)
	alice, _ := s.getClient("alice")
	aliceMem := &channel.Member{Client: alice}
	local.SetMember(aliceMem)
	s.setChannel(local)

	t.Run("ExactChannel", func(t *testing.T) {
		c1.Write([]byte("WHO #local\r\n"))
		resp, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 352 alice #local alice localhost %s alice H :0 alice\r\n", s.Name, s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice #local :End of WHO list\r\n", s.Name), t)
	})

	t.Run("AwayOpsVoice", func(t *testing.T) {
		aliceMem.Mode |= client.Away | client.Op
		aliceMem.Prefix = string(channel.Operator) + string(channel.Voice)
		c1.Write([]byte("WHO #local\r\n"))
		resp, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 352 alice #local alice localhost %s alice G*@+ :0 alice\r\n", s.Name, s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice #local :End of WHO list\r\n", s.Name), t)
	})

	c2, _ := connectAndRegister("bob")
	defer c2.Close()

	// bob is invisible, so he should not show up in the general WHO list
	t.Run("Invisible", func(t *testing.T) {
		bob, _ := s.getClient("bob")
		bob.Mode |= client.Invisible

		c1.Write([]byte("WHO\r\n"))
		resp, _ := r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 352 alice * alice localhost %s alice G* :0 alice\r\n", s.Name, s.Name), t)
		assertResponse(end, fmt.Sprintf(":%s 315 alice * :End of WHO list\r\n", s.Name), t)
	})

	// when bob joins a channel that alice is also joined to, they now
	// show up when alice requests a general WHO
	t.Run("InvisibleButJoined", func(t *testing.T) {
		bob, _ := s.getClient("bob")
		local.SetMember(&channel.Member{Client: bob})

		c1.Write([]byte("WHO\r\n"))
		// should get two WHOREPLY, one for alice and one for bob; they can come in any order which is why don't check here
		r1.ReadBytes('\n')
		r1.ReadBytes('\n')
		end, _ := r1.ReadBytes('\n')
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

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	c1.Write([]byte("WHOIS bob\r\n"))
	whois, _ := r1.ReadBytes('\n')
	server, _ := r1.ReadBytes('\n')
	r1.ReadBytes('\n') // TODO: check bob idle and join time
	chans, _ := r1.ReadBytes('\n')
	end, _ := r1.ReadBytes('\n')

	assertResponse(whois, fmt.Sprintf(":%s 311 alice bob bob %s * :bob\r\n", s.Name, "localhost"), t)
	assertResponse(server, fmt.Sprintf(":%s 312 alice bob %s :wip irc server\r\n", s.Name, s.Name), t)
	// assertResponse(idle, fmt.Sprintf(":%s 317 alice bob %v %v :seconds idle, signon time\r\n", s.Name, time.Since(bob.Idle).Round(time.Second).Seconds(), bob.JoinTime), t)
	assertResponse(chans, fmt.Sprintf(":%s 319 alice bob\r\n", s.Name), t)
	assertResponse(end, fmt.Sprintf(":%s 318 alice bob :End of /WHOIS list\r\n", s.Name), t)

	t.Run("TestAWAY", func(t *testing.T) {
		c2.Write([]byte("AWAY :I'm away\r\n"))
		r2.ReadBytes('\n')
		c1.Write([]byte("WHOIS bob\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, ":gossip 301 alice bob :I'm away\r\n", t)
	})
}

func TestWHOWAS(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	t.Run("TestMultipleEntries", func(t *testing.T) {
		c1, r1 := connectAndRegister("alice")
		c1.Write([]byte("QUIT\r\n"))
		r1.ReadBytes('\n')
		defer c1.Close()
		c2, r2 := connectAndRegister("alice")
		c2.Write([]byte("QUIT\r\n"))
		r2.ReadBytes('\n')
		defer c2.Close()

		c3, r3 := connectAndRegister("bob")
		defer c3.Close()

		c3.Write([]byte("WHOWAS alice\r\n"))
		resp1, _ := r3.ReadBytes('\n')
		assertResponse(resp1, fmt.Sprintf(RPL_WHOWASUSER+"\r\n", s.Name, "bob", "alice", "alice", "localhost", "alice"), t)
		resp2, _ := r3.ReadBytes('\n')
		assertResponse(resp2, fmt.Sprintf(RPL_WHOWASUSER+"\r\n", s.Name, "bob", "alice", "alice", "localhost", "alice"), t)
		end, _ := r3.ReadBytes('\n')
		assertResponse(end, fmt.Sprintf(RPL_ENDOFWHOWAS+"\r\n", s.Name, "bob", "alice"), t)
	})

	t.Run("TestCount1", func(t *testing.T) {
		c1, r1 := connectAndRegister("alice")
		c1.Write([]byte("QUIT\r\n"))
		r1.ReadBytes('\n')
		defer c1.Close()
		c2, r2 := connectAndRegister("alice")
		c2.Write([]byte("QUIT\r\n"))
		r2.ReadBytes('\n')
		defer c2.Close()

		c3, r3 := connectAndRegister("bob")
		defer c3.Close()

		c3.Write([]byte("WHOWAS alice 1\r\n"))
		resp, _ := r3.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(RPL_WHOWASUSER+"\r\n", s.Name, "bob", "alice", "alice", "localhost", "alice"), t)
		end, _ := r3.ReadBytes('\n')
		assertResponse(end, fmt.Sprintf(RPL_ENDOFWHOWAS+"\r\n", s.Name, "bob", "alice"), t)
	})
}

func TestChanFull(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
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

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
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

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
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

func TestINVITE(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	c1.Write([]byte("JOIN #local\r\n"))
	c1.Write([]byte("MODE #local +i\r\n"))
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')
	r1.ReadBytes('\n')

	t.Run("TestMissingParam", func(t *testing.T) {
		c1.Write([]byte("INVITE\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 alice INVITE :Not enough parameters\r\n", t)
	})

	t.Run("NoSuchChannel", func(t *testing.T) {
		c1.Write([]byte("INVITE bob #notExist\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 403 alice #notExist :No such channel\r\n", s.Name), t)
	})

	t.Run("NotOnChannel", func(t *testing.T) {
		c2.Write([]byte("INVITE alice #local\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(":%s 442 bob #local :You're not on that channel\r\n", s.Name), t)
	})

	t.Run("JoinInviteModedChannelWithoutBeingInvited", func(t *testing.T) {
		c2.Write([]byte("JOIN #local\r\n"))
		resp, _ := r2.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(":%s 473 bob #local :Cannot join channel (+i)\r\n", s.Name), t)
	})

	t.Run("JoinInviteModedChannelAfterInvite", func(t *testing.T) {
		c1.Write([]byte("INVITE bob #local\r\n"))
		inviteResp, _ := r1.ReadBytes('\n')
		assertResponse(inviteResp, ":gossip 341 alice bob #local\r\n", t)

		receivedInvite, _ := r2.ReadBytes('\n')
		assertResponse(receivedInvite, ":alice!alice@localhost INVITE bob #local\r\n", t)

		c2.Write([]byte("JOIN #local\r\n"))
		resp, _ := r2.ReadBytes('\n')
		r2.ReadBytes('\n')
		r2.ReadBytes('\n')
		r1.ReadBytes('\n') // read bob's join message

		assertResponse(resp, ":bob!bob@localhost JOIN #local\r\n", t)
	})

	t.Run("NoPrivileges", func(t *testing.T) {
		c2.Write([]byte("INVITE somebody #local\r\n"))
		resp, _ := r2.ReadBytes('\n')

		assertResponse(resp, ":gossip 482 bob #local :You're not a channel operator\r\n", t)
	})

	t.Run("NoSuchNick", func(t *testing.T) {
		c1.Write([]byte("INVITE somebody #local\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 401 alice somebody :No such nick/channel\r\n", t)
	})

	t.Run("AlreadyInvited", func(t *testing.T) {
		c1.Write([]byte("INVITE bob #local\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 443 alice bob #local :is already on channel\r\n", t)
	})
}

func TestBan(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
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

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	local := channel.New("local", '#')
	s.setChannel(local)
	local.SetMember(&channel.Member{Client: s.clients["alice"], Prefix: string(channel.Operator)})
	local.SetMember(&channel.Member{Client: s.clients["bob"]})

	t.Run("TestNoTextToSend", func(t *testing.T) {
		c1.Write([]byte("PRIVMSG bob\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(ERR_NOTEXTTOSEND+"\r\n", s.Name, "alice"), t)
	})

	t.Run("TestClientPRIVMSG", func(t *testing.T) {
		// alice sends message to bob
		c1.Write([]byte("PRIVMSG bob :hello\r\n"))
		msgResp, _ := r2.ReadBytes('\n')
		assertResponse(msgResp, ":alice!alice@localhost PRIVMSG bob :hello\r\n", t)
	})

	t.Run("TestNoSuchNick", func(t *testing.T) {
		c1.Write([]byte("PRIVMSG notReal :hello\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(ERR_NOSUCHNICK+"\r\n", s.Name, "alice", "notReal"), t)
	})

	t.Run("TestChannelPRIVMSG", func(t *testing.T) {
		// message sent to channel should broadcast to all members
		c1.Write([]byte("PRIVMSG #local :hello\r\n"))
		resp, _ := r2.ReadBytes('\n')
		assertResponse(resp, ":alice!alice@localhost PRIVMSG #local :hello\r\n", t)
	})

	t.Run("TestNoSuchChan", func(t *testing.T) {
		c1.Write([]byte("PRIVMSG #notFound :hello\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(ERR_NOSUCHCHANNEL+"\r\n", s.Name, "alice", "#notFound"), t)
	})

	t.Run("TestMultipleTargets", func(t *testing.T) {
		c3, _ := connectAndRegister("c")
		defer c3.Close()

		local.SetMember(&channel.Member{Client: s.clients["c"]})

		c3.Write([]byte("PRIVMSG #local,bob :From c\r\n"))
		chanResp1, _ := r1.ReadBytes('\n')
		chanResp2, _ := r2.ReadBytes('\n')
		privmsgResp, _ := r2.ReadBytes('\n')
		assertResponse(chanResp1, ":c!c@localhost PRIVMSG #local :From c\r\n", t)
		assertResponse(chanResp2, ":c!c@localhost PRIVMSG #local :From c\r\n", t)
		assertResponse(privmsgResp, ":c!c@localhost PRIVMSG bob :From c\r\n", t)
	})
}

func TestChannelPRIVMSGTags(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()
	c3, r3 := connectAndRegister("carl")
	defer c3.Close()

	c1.Write([]byte("CAP REQ message-tags\r\n"))
	r1.ReadBytes('\n')
	c2.Write([]byte("CAP REQ :message-tags echo-message\r\n"))
	r2.ReadBytes('\n')

	alice, _ := s.getClient("alice")
	bob, _ := s.getClient("bob")
	carl, _ := s.getClient("carl")
	local := channel.New("local", channel.Remote)
	local.SetMember(&channel.Member{Client: alice, Prefix: string(channel.Founder)})
	local.SetMember(&channel.Member{Client: bob})
	local.SetMember(&channel.Member{Client: carl})
	s.setChannel(local)

	c1.Write([]byte("@+foo=bar;shouldBe=skipped PRIVMSG #local :hey\r\n"))
	resp, _ := r2.ReadBytes('\n')
	if !strings.Contains(string(resp), "+foo=bar") && !strings.Contains(string(resp), alice.String()+"PRIVMSG #local :hey\r\n") {
		t.Fail()
	}

	resp, _ = r3.ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(":%s PRIVMSG #local :hey\r\n", alice), t)
}

func TestPING(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("a")
	defer c.Close()

	c.Write([]byte("PING token\r\n"))
	resp, _ := r.ReadBytes('\n')

	assertResponse(resp, ":gossip PONG gossip token\r\n", t)
}

func TestPONG(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := &client.Client{PONG: make(chan struct{}, 1)}
	s.clients["c"] = c

	PONG(s, c, nil)

	select {
	case <-c.PONG:
	default:
		t.Error("did not receive PONG")
	}
}

func TestAWAY(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
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

func TestUSERHOST(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	t.Run("TestNotAway", func(t *testing.T) {
		c1.Write([]byte("USERHOST bob\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(RPL_USERHOST+"\r\n", s.Name, "alice", "bob=+localhost"), t)
	})
	t.Run("TestAway", func(t *testing.T) {
		c2.Write([]byte("AWAY :I'm away\r\n"))
		r2.ReadBytes('\n')

		c1.Write([]byte("USERHOST bob\r\n"))
		resp, _ := r1.ReadBytes('\n')
		assertResponse(resp, fmt.Sprintf(RPL_USERHOST+"\r\n", s.Name, "alice", "bob=-localhost"), t)
	})
}

func TestWALLOPS(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c1, r1 := connectAndRegister("alice")
	defer c1.Close()
	c2, r2 := connectAndRegister("bob")
	defer c2.Close()

	c2.Write([]byte("MODE bob +w\r\n"))
	r2.ReadBytes('\n')

	alice, _ := s.getClient("alice")

	c1.Write([]byte("WALLOPS test\r\n"))
	resp, _ := r2.ReadBytes('\n')
	assertResponse(resp, fmt.Sprintf(":%s WALLOPS test\r\n", alice), t)

	t.Run("TestMissingParam", func(t *testing.T) {
		c1.Write([]byte("WALLOPS\r\n"))
		resp, _ := r1.ReadBytes('\n')

		assertResponse(resp, ":gossip 461 alice WALLOPS :Not enough parameters\r\n", t)
	})
}

func TestREHASH(t *testing.T) {
	conf.configSource = strings.NewReader(`{"name": "gossip"}`)
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("a")
	defer c.Close()

	t.Run("NoPriviliges", func(t *testing.T) {
		c.Write([]byte("REHASH\r\n"))
		resp, _ := r.ReadBytes('\n')

		assertResponse(resp, fmt.Sprintf(ERR_NOPRIVILEGES+"\r\n", s.Name, "a"), t)
	})
}

func TestUnknownCommand(t *testing.T) {
	s, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()

	c, r := connectAndRegister("a")
	defer c.Close()

	c.Write([]byte("UnknownCommand\r\n"))
	resp, _ := r.ReadBytes('\n')

	assertResponse(resp, ":gossip 421 a UnknownCommand :Unknown command\r\n", t)
}
