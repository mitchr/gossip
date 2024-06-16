//go:build ext_vectors

package wild

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

type MaskMatchTest struct {
	Tests []struct {
		Mask    string
		Matches []string
		Fails   []string
	}
}

func TestMaskMatch(t *testing.T) {
	var maskMatchTests *MaskMatchTest
	f, err := os.ReadFile("../../../parser-tests/tests/mask-match.yaml")
	if err != nil {
		t.Fatal()
	}
	err = yaml.Unmarshal(f, &maskMatchTests)
	if err != nil {
		t.Fatal()
	}

	for _, v := range maskMatchTests.Tests {
		// success
		for _, s := range v.Matches {
			if !Match(v.Mask, s) {
				t.Error(s, "did not match with mask", v.Mask)
			}
		}

		// fail
		for _, s := range v.Fails {
			if Match(v.Mask, s) {
				t.Error(s, "should not have matched with mask", v.Mask)
			}
		}
	}
}
