package mode

import (
	"reflect"
	"testing"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		i        string
		add, sub []rune
	}{
		{"+m", []rune{'m'}, nil},
		{"+mb", []rune{'m', 'b'}, nil},
		{"-i", nil, []rune{'i'}},
		{"+a-i", []rune{'a'}, []rune{'i'}},
		{"+a+b+c-de+f-g", []rune{'a', 'b', 'c', 'f'}, []rune{'d', 'e', 'g'}},
	}

	for _, v := range tests {
		a, s := Parse([]byte(v.i))
		if !reflect.DeepEqual(a, v.add) || !reflect.DeepEqual(s, v.sub) {
			t.Error(a, v.add, s, v.sub)
		}
	}
}
