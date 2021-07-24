package pf

// Anchor is a pf firewall anchor struct
type Anchor struct {
	Name    string
	RuleSet RuleSet
}

// NewAnchor returns a new Anchor struct. It requires an anchor name as parameter
func (f *Firewall) NewAnchor(n string) Anchor {
	anchorObj := Anchor{
		Name: n,
	}
	return anchorObj
}

// NewRule generates a new Rule with sane defaults
func (a *Anchor) NewRule() Rule {
	ar := Rule{}
	ar.SetAction(ActionBlock)
	return ar
}

// AddRule adds a given rule to the Anchor RuleSet struct rules array. The rule must have the committed
// flag set to true
func (a *Anchor) AddRule(r Rule) {
	if r.committed {
		a.RuleSet.AddRule(r)
	}
}

// RulesString returns a line separated string of all committed rules of the current Anchor
func (a *Anchor) RulesString() string {
	return a.RuleSet.RulesString()
}
