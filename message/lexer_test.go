package message

import (
	"fmt"
	"reflect"
	"testing"
)

func TestLexParams(t *testing.T) {
	tests := map[string][]token{
		" CAP * LIST\r\n":              {{space, " "}, {nospcrlfcl, "CAP"}, {space, " "}, {nospcrlfcl, "*"}, {space, " "}, {nospcrlfcl, "LIST"}, {crlf, "\r\n"}},
		" * LS :multi-prefix sasl\r\n": {{space, " "}, {nospcrlfcl, "*"}, {space, " "}, {nospcrlfcl, "LS"}, {space, " "}, {colon, ":"}, {nospcrlfcl, "multi-prefix"}, {space, " "}, {nospcrlfcl, "sasl"}, {crlf, "\r\n"}},

		// " REQ :sasl message-tags foo": {{middle, "REQ"}, {trailing, "sasl message-tags foo"}},
		// " #chan :Hey!":                {{middle, "#chan"}, {trailing, "Hey!"}},
		// " #chan Hey!":                 {{middle, "#chan"}, {middle, "Hey!"}},
		// "        #chan       Hey!":    {{middle, "#chan"}, {middle, "Hey!"}}, // variation with extra whitespace
	}

	for k, v := range tests {
		t.Run(k, func(t *testing.T) {
			if !reflect.DeepEqual(lex([]byte(k)), v) {
				fmt.Println(lex([]byte(k)))
				t.Errorf("Failed to lex %s\n", k)
			}
		})
	}
}
