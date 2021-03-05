package client

import (
	"fmt"
	"testing"
)

func TestModeApplication(t *testing.T) {
	tests := [][]byte{
		[]byte("+i"),
		[]byte("+ir"),
	}
	for _, v := range tests {
		c := &Client{}
		c.ApplyMode(v)
		fmt.Println(c.Mode)
	}

	c := &Client{}
	c.ApplyMode([]byte("+i-i"))
	// c.ApplyMode([]byte("-i"))
	fmt.Println(c.Mode, uint(c.Mode))
}
