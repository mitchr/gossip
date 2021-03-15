package mode

import (
	"reflect"
	"testing"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		i string
		m []Mode
	}{
		{"+m", []Mode{{'m', true, ""}}},
		{"+mb", []Mode{{'m', true, ""}, {'b', true, ""}}},
		{"-i", []Mode{{'i', false, ""}}},
		{"+a-i", []Mode{{'a', true, ""}, {'i', false, ""}}},
		// {"+a+b+c-de+f-g", []rune{'a', 'b', 'c', 'f'}, []rune{'d', 'e', 'g'}},
	}

	for _, v := range tests {
		t.Run(v.i, func(t *testing.T) {
			m := Parse([]byte(v.i))
			if !reflect.DeepEqual(m, v.m) {
				t.Error(m, v.m)
			}
		})
	}
}
