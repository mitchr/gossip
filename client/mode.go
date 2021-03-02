package client

type Mode int

const (
	None       Mode = 0
	Registered Mode = 1 << iota
	Invisible
	Wallops
	Away // TODO: should include this here? AWAY is weird
	Op
	LocalOp
)

func applyMode(s string, c *Client) {

}
