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
		{"+m", []Mode{{'m', Add, ""}}},
		{"+mb", []Mode{{'m', Add, ""}, {'b', Add, ""}}},
		{"-i", []Mode{{'i', Remove, ""}}},
		{"+a-i", []Mode{{'a', Add, ""}, {'i', Remove, ""}}},
		{"i", []Mode{{'i', List, ""}}},
		{"beI", []Mode{{'b', List, ""}, {'e', List, ""}, {'I', List, ""}}},
		{"+a+b+c-de+f-g",
			[]Mode{
				{'a', Add, ""},
				{'b', Add, ""},
				{'c', Add, ""},
				{'d', Remove, ""},
				{'e', Remove, ""},
				{'f', Add, ""},
				{'g', Remove, ""},
			},
		},
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
