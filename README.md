# `gossip` ![build status](https://github.com/mitchr/gossip/actions/workflows/go.yml/badge.svg)
`gossip` is an IRC server.

## Install
`go get github.com/mitchr/gossip`

## Usage
`gossip` by default looks for a file in the same directory as it called [config.json](config.json). You can change this location by using `gossip -conf=<path>` This defines things like the name of the server and the port. To use TLS, you have to specify paths to `pubkey` and `privkey`.

To add a server password, use `gossip -s`. This will prompt you to enter a password and then save the bcrypt-ed hash in `config.json`. Similarly to add a new server operator, you can use `gossip -o`.

## References
- [RFC 1459](https://datatracker.ietf.org/doc/html/rfc1459)
- [RFC 2812](https://datatracker.ietf.org/doc/html/rfc2812)
- [IRCv3](https://ircv3.net/irc/)
- [Modern IRC Client Protocol](https://modern.ircdocs.horse/)

## External Licenses
`golang.org/x/crypto` and `golang.org/x/term` are licensed under the BSD-3-Clause, reproduced below

```
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```