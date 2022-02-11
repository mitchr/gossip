package wild

import "testing"

func TestMatchEscape(t *testing.T) {
	tests := []struct {
		regex, match string
		doesMatch    bool
	}{
		{`abc\*`, "abc*", true},
		{`lucky\*lucky`, "lucky*lucky", true},
		{`lucky\*lucky`, "luckySTARlucky", false},
		{`esc\`, "esc", false},
		{`http:\google.com`, `http:\google.com`, true},
		{`http:\\google.*`, `http:\\google.\*`, true},
		{`http:\\google.*`, `http:\\google.com`, true},
	}

	for _, v := range tests {
		t.Run(v.regex, func(t *testing.T) {
			if Match(v.regex, v.match) != v.doesMatch {
				t.Error(v.regex, v.match)
			}
		})
	}
}

func TestMatchNowildesc(t *testing.T) {
	tests := []struct {
		regex, match string
		doesMatch    bool
	}{
		{"abc", "abc", true},
		{"abc 1 2 3", "abc 1 2 3", true},
		{"abc 1 2 3", "abc 1 2 4", false},
	}

	for _, v := range tests {
		t.Run(v.regex, func(t *testing.T) {
			if Match(v.regex, v.match) != v.doesMatch {
				t.Error(v.regex, v.match)
			}
		})
	}
}

func TestMatchWildone(t *testing.T) {
	tests := []struct {
		regex, match string
		doesMatch    bool
	}{
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "atoomuchc", false},
		{"?", " ", true},
		// {"?", "", false},
	}

	for _, v := range tests {
		t.Run(v.regex, func(t *testing.T) {
			if Match(v.regex, v.match) != v.doesMatch {
				t.Error(v.regex, v.match)
			}
		})
	}
}

func TestMatchWildmany(t *testing.T) {
	tests := []struct {
		regex, match string
		doesMatch    bool
	}{
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "a anything goes c", true},
		{"a*c", "a never got there", false},
		{"100.*.*.*", "100.9.1.9", true},
		{"bob!*@*", "bob!Bob@127.0.0.1:99023", true},
		{"*@127.0.0.1", "james@127.0.0.1", true},
		{"*@127.0.0.1", "@127.0.0.1", true},
		{"*", "", true},
		{"*", "?", true},
	}

	for _, v := range tests {
		t.Run(v.regex, func(t *testing.T) {
			if Match(v.regex, v.match) != v.doesMatch {
				t.Error(v.regex, v.match)
			}
		})
	}
}
