package channel

import "testing"

func TestMemberModeApplication(t *testing.T) {
	tests := []struct {
		modeStr, prefix string
	}{
		{"+q", string(Founder)},
		{"+ov", string(Operator) + string(Voice)},
		{"+a-a", ""},
		{"+zyx", ""}, //nonexistant modes
		{"-zyx", ""}, //nonexistant modes
	}

	for _, v := range tests {
		m := &Member{}
		m.ApplyMode([]byte(v.modeStr))
		if m.prefixes != v.prefix {
			t.Error(v, m.prefixes, v.prefix)
		}
	}
}
