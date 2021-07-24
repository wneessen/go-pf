package pf

import (
	"fmt"
	"net"
)

// GetRules returns a string array of currently configured firewall rules
func (f *Firewall) GetRules() ([]string, error) {
	return f.execPfCtl("-s", "rules")
}

// Rule is the struct that holds all relevant data for a pf firewall anchor rule
type Rule struct {
	Action       string
	AdressFamily string
	Commited     bool
	Direction    string
	Destination  net.IPNet
	DestPort     uint32
	Interface    string
	Log          bool
	Protocol     string
	Source       net.IPNet
	SourcePort   uint32
}

// SetSourceIP sets a source IP for the current Rule
func (a *Rule) SetSourceIP(i string, m ...string) {
	if !a.Commited {
		a.Source = parseIP(i, m)
	}
}

// SetSourceCIDR sets a source IP for the current Rule
func (a *Rule) SetSourceCIDR(c string) error {
	if !a.Commited {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return err
		}
		a.Source = *ipNet
	}
	return nil
}

// SetDestinationIP sets a destination IP for the current Rule
func (a *Rule) SetDestinationIP(i string, m ...string) {
	if !a.Commited {
		a.Destination = parseIP(i, m)
	}
}

// SetDestinationCIDR sets a source IP for the current Rule
func (a *Rule) SetDestinationCIDR(c string) error {
	if !a.Commited {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return err
		}
		a.Source = *ipNet
	}
	return nil
}

// SetSourcePort sets the source port for the current Rule
func (a *Rule) SetSourcePort(p uint32) {
	if !a.Commited {
		a.SourcePort = p
	}
}

// SetDestinationPort sets the source port for the current Rule
func (a *Rule) SetDestinationPort(p uint32) {
	if !a.Commited {
		a.DestPort = p
	}
}

// SetInterface sets the interface for the current Rule
func (a *Rule) SetInterface(i string) {
	if !a.Commited {
		a.Interface = i
	}
}

// SetProtocol sets the protocol type for the current Rule
func (a *Rule) SetProtocol(p PfProtocol) {
	if !a.Commited {
		switch p {
		case ProtocolTcp:
			a.Protocol = "tcp"
		case ProtocolUdp:
			a.Protocol = "udp"
		case ProtocolIcmp:
			a.Protocol = "icmp"
		case ProtocolIcmpv6:
			a.Protocol = "icmp6"
		default:
			a.Protocol = ""
		}
	}
}

// SetAction sets the action type for the current Rule
func (a *Rule) SetAction(ac PfAction) {
	if !a.Commited {
		switch ac {
		case ActionPass:
			a.Action = "pass"
		case ActionBlock:
			a.Action = "block"
		default:
			a.Action = "block"
		}
	}
}

// SetAddrFamily sets the address family for the current Rule
func (a *Rule) SetAddrFamily(f PfAddrFam) {
	if !a.Commited {
		switch f {
		case AdressFamilyInet:
			a.AdressFamily = "inet"
		case AdressFamilyInetv6:
			a.AdressFamily = "inet6"
		default:
			a.AdressFamily = ""
		}
	}
}

// SetDirection sets the address family for the current Rule
func (a *Rule) SetDirection(d PfDirection) {
	if !a.Commited {
		switch d {
		case DirectionIn:
			a.Direction = "in"
		case DirectionOut:
			a.Direction = "out"
		default:
			a.Direction = ""
		}
	}
}

// SetLogging enables logging for the current Rule
func (a *Rule) SetLogging() {
	a.Log = true
}

// Commit commits the current Rule so it is immutable
func (a *Rule) Commit() {
	a.Commited = true
}

// String parses a given Rule and returns the full rule as string
func (a *Rule) String() string {
	var fwRule string
	if a.Action != "" {
		fwRule = a.Action
	}
	if a.Direction != "" {
		fwRule = fmt.Sprintf("%s %s", fwRule, a.Direction)
	}
	if a.Log {
		fwRule = fmt.Sprintf("%s log", fwRule)
	}
	if a.Interface != "" {
		fwRule = fmt.Sprintf("%s on %s", fwRule, a.Interface)
	}
	if a.AdressFamily != "" {
		fwRule = fmt.Sprintf("%s on %s", fwRule, a.Interface)
	}
	if a.Protocol != "" {
		fwRule = fmt.Sprintf("%s proto %s", fwRule, a.Protocol)
	}
	if a.Source.String() != "" || a.SourcePort > 0 {
		if a.Source.String() != "" {
			fwRule = fmt.Sprintf("%s from %s", fwRule, a.Source.String())
		} else {
			fwRule = fmt.Sprintf("%s from any", fwRule)
		}
		if a.SourcePort > 0 {
			fwRule = fmt.Sprintf("%s port %d", fwRule, a.SourcePort)
		}
	}
	if a.Destination.String() != "" || a.DestPort > 0 {
		if a.Destination.String() != "" {
			fwRule = fmt.Sprintf("%s to %s", fwRule, a.Destination.String())
		} else {
			fwRule = fmt.Sprintf("%s to any", fwRule)
		}
		if a.DestPort > 0 {
			fwRule = fmt.Sprintf("%s port %d", fwRule, a.DestPort)
		}
	}

	return fwRule
}
