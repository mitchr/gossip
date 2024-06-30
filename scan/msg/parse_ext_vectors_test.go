//go:build ext_vectors

package msg

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mitchr/gossip/scan"
	"gopkg.in/yaml.v3"
)

type MsgJoinTest struct {
	Tests []struct {
		Desc  string
		Atoms struct {
			Source string
			Verb   string
			Params []string
			Tags   map[string]interface{}
		}
		Matches []string
	}
}

func TestMsgJoin(t *testing.T) {
	var msgJoinTests *MsgJoinTest
	f, err := os.ReadFile("../../../parser-tests/tests/msg-join.yaml")
	if err != nil {
		t.Fatal()
	}
	err = yaml.Unmarshal(f, &msgJoinTests)
	if err != nil {
		t.Fatal()
	}

	// for each 'matches' case, verify that we parsed the atoms correctly
	for _, v := range msgJoinTests.Tests {
		for _, c := range v.Matches {
			m, err := Parse(&scan.Parser{Lexer: scan.Lex([]byte(c+"\r\n"), LexMessage)})
			if err != nil {
				t.Error("error when parsing", c, ":", err)
			}

			if m.Nick != v.Atoms.Source {
				t.Error("failed to parse source; wanted", v.Atoms.Source, "but got", m.Nick)
			}
			if m.Command != strings.ToUpper(v.Atoms.Verb) {
				t.Error("failed to parse verb; wanted", strings.ToUpper(v.Atoms.Verb), "but got", m.Command)
			}
			if !reflect.DeepEqual(m.Params, v.Atoms.Params) {
				t.Error("failed to parse params; wanted", v.Atoms.Params, "but got", m.Params)
			}

			// tag check
			for k, tag := range v.Atoms.Tags {
				if ok, _ := m.HasTag(k); !ok {
					t.Error("failed to parse tag; wanted", k, "but got nothing")
				}

				// search our output tags looking for the tag key; check if that key has the correct value
				for _, j := range m.tags {
					if j.Key == k {
						if j.Raw() != tag {
							t.Error("failed to parse tag; wanted", tag, "but got", j.Raw())
						}
					}
				}
			}
		}
	}
}

type MsgSplitTest struct {
	Tests []struct {
		Input string
		Atoms struct {
			Source string
			Verb   string
			Params []string
			Tags   map[string]interface{}
		}
	}
}

func TestMsgSplit(t *testing.T) {
	var msgSplitTests *MsgSplitTest
	f, err := os.ReadFile("../../../parser-tests/tests/msg-split.yaml")
	if err != nil {
		t.Fatal()
	}
	err = yaml.Unmarshal(f, &msgSplitTests)
	if err != nil {
		t.Fatal()
	}

	for _, v := range msgSplitTests.Tests {
		m, err := Parse(&scan.Parser{Lexer: scan.Lex([]byte(v.Input+"\r\n"), LexMessage)})
		if err != nil {
			t.Error("error when parsing", v.Input, ":", err)
		}

		if m.NUH() != v.Atoms.Source {
			t.Error("failed to parse source; wanted", v.Atoms.Source, "but got", m.NUH())
		}
		if m.Command != strings.ToUpper(v.Atoms.Verb) {
			t.Error("failed to parse verb; wanted", strings.ToUpper(v.Atoms.Verb), "but got", m.Command)
		}
		if !reflect.DeepEqual(m.Params, v.Atoms.Params) {
			t.Error("failed to parse params; wanted", v.Atoms.Params, "but got", m.Params)
		}

		// tag check
		for k, tag := range v.Atoms.Tags {
			if ok, _ := m.HasTag(k); !ok {
				t.Error("failed to parse tag; wanted", k, "but got nothing")
			}

			// search our output tags looking for the tag key; check if that key has the correct value
			for _, j := range m.tags {
				if j.Key == k {
					if j.Raw() != tag {
						t.Error("failed to parse tag; wanted", tag, "but got", j.Raw())
					}
				}
			}
		}
	}
}

type UserHostSplitTest struct {
	Tests []struct {
		Source string
		Atoms  struct {
			Nick string
			User string
			Host string
		}
	}
}

func TestUserHostSplit(t *testing.T) {
	var userHostSplitTests *UserHostSplitTest
	f, err := os.ReadFile("../../../parser-tests/tests/userhost-split.yaml")
	if err != nil {
		t.Fatal()
	}
	err = yaml.Unmarshal(f, &userHostSplitTests)
	if err != nil {
		t.Fatal()
	}

	for _, v := range userHostSplitTests.Tests {
		p := &scan.Parser{Lexer: scan.Lex([]byte(v.Source), LexMessage)}
		nick, user, host := source(p)

		if nick != v.Atoms.Nick {
			t.Error("failed to parse nick; wanted", v.Atoms.Nick, "but got", nick)
		}
		if user != v.Atoms.User {
			t.Error("failed to parse user; wanted", v.Atoms.User, "but got", user)
		}
		if host != v.Atoms.Host {
			t.Error("failed to parse host; wanted", v.Atoms.Host, "but got", host)
		}
	}
}
