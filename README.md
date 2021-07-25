# go-pf - FreeBSD pf wrapper in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/wneessen/go-pf.svg)](https://pkg.go.dev/github.com/wneessen/go-pf?GOOS=darwin) [![Go Report Card](https://goreportcard.com/badge/github.com/wneessen/go-pf)](https://goreportcard.com/report/github.com/wneessen/go-pf) [![Build Status](https://api.cirrus-ci.com/github/wneessen/go-pf.svg)](https://cirrus-ci.com/github/wneessen/go-pf)

Is a Go module that wraps around the FreeBSD pf (packet filter). It uses the pfctl command for all
operations on the /dev/pf interface

The project currently only supports the functionality I require for a personal project. Contributions
are welcome, though.
