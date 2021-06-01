# `gossip` ![build status](https://github.com/mitchr/gossip/workflows/Go/badge.svg)
`gossip` is an IRC server.

## Install
`go get github.com/mitchr/gossip`

## Usage
`gossip` looks for a file in the same directory as it called [config.json](config.json). This defines things like the name of the server and the port. To use TLS, you have to specify paths to `pubkey` and `privkey`.

To add a server password, use `gossip -s`. This will prompt you to enter a password and then save the bcrypt-ed has in `config.json`. Similarly to add a new server operator, you can use `gossip -o`.

## References
- [RFC 1459](https://datatracker.ietf.org/doc/html/rfc1459)
- [RFC 2812](https://datatracker.ietf.org/doc/html/rfc2812)
- [IRCv3](https://ircv3.net/irc/)
- [Modern IRC Client Protocol](https://modern.ircdocs.horse/)