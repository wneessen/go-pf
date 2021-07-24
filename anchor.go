// +build !windows,!plan9,!linux

package pf

import (
	"bytes"
)

// Anchor is a pf firewall anchor struct
type Anchor struct {
	Name    string
	RuleSet RuleSet
	FwObj   *Firewall
}

// New returns a new Anchor struct. It requires an anchor name as parameter
func (f *Firewall) NewAnchor(n string) Anchor {
	anchorObj := Anchor{
		Name:  n,
		FwObj: f,
	}
	return anchorObj
}

// NewRule generates a new Rule with sane defaults
func (a *Anchor) NewRule() Rule {
	ar := Rule{}
	ar.SetAction(ActionBlock)
	return ar
}

// AddRule adds a given rule to the Anchor RuleSet struct rules array. The rule must have the commited
// flag set to true
func (a *Anchor) AddRule(r Rule) {
	if r.Commited {
		a.RuleSet.AddRule(r)
	}
}

// GetRulesString returns a line separated string of all commited rules of the current Anchor
func (a *Anchor) RulesString() string {
	return a.RuleSet.RulesString()
}

// Commit takes all commited RuleSet of the current Anchor and commits them as ruleset to the
// pfctl anchor
func (a *Anchor) Commit() error {
	var byteBuffer bytes.Buffer
	var err error
	ruleSet := a.RuleSet.RulesString() + "\n"

	_, err = byteBuffer.Write([]byte(ruleSet))
	if err != nil {
		return err
	}

	_, err = a.FwObj.execPfCtlStdin(byteBuffer, "-a", a.Name, "-f", "-", "-v")
	if err != nil {
		return err
	}

	return nil
}
