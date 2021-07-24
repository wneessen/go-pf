package pf

import "strings"

// RuleSet represents a set of firewall rules
type RuleSet struct {
	Rules []Rule
}

// AddRule adds a given rule to the RuleSet struct rules array. The rule must have the commited
// flag set to true
func (rs *RuleSet) AddRule(r Rule) {
	if r.Commited {
		rs.Rules = append(rs.Rules, r)
	}
}

// GetRules returns a string array of all commited rules of the current RuleSet
func (rs *RuleSet) GetRules() []string {
	ruleArray := make([]string, 0)
	for _, r := range rs.Rules {
		if r.Commited {
			ruleArray = append(ruleArray, r.String())
		}
	}
	return ruleArray
}

// GetRulesString returns a line separated string of all commited rules of the current RuleSet
func (rs *RuleSet) RulesString() string {
	ruleArray := make([]string, 0)
	for _, r := range rs.Rules {
		if r.Commited {
			ruleArray = append(ruleArray, r.String())
		}
	}
	return strings.Join(ruleArray, "\n")
}
