package client

import (
	"bufio"
	"fmt"
	"net"
	"testing"

	"github.com/mitchr/gossip/capability"
	"github.com/mitchr/gossip/sasl"
	"github.com/mitchr/gossip/scan/msg"
)

func TestWriteMessageFrom(t *testing.T) {

	t.Run("ShouldNotIncludeMessageTagsIfNotRequested", func(t *testing.T) {
		from := &Client{}
		from.Caps = make(map[string]bool)
		from.SASLMech = sasl.None{}
		from.Mode = Bot
		from.Caps[capability.MessageTags.Name] = true

		in, out := net.Pipe()
		c := New(in)
		c.WriteMessageFrom(msg.New(nil, "a", "", "", "PRIVMSG", []string{"b"}, false), from)
		go c.Flush()

		resp, _ := bufio.NewReader(out).ReadString('\n')
		if resp != ":a PRIVMSG b\r\n" {
			fmt.Println(resp)
			t.Error("sent message-tags without requesting them")
		}
	})
}
