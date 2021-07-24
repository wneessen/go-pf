package pf

import (
	"fmt"
	"log"
	"net"
)

// GetTables returns a string array of currently configured firewall table
func (f *Firewall) GetTables() ([]string, error) {
	return f.execPfCtl("-s", "Tables")
}

// AddToTableCIDR adds one or more CIDR entries to a pf radix table.
// Returns error on parsing failures or execution issues
func (f *Firewall) AddToTableCIDR(t string, e ...string) error {
	errArray := make([]error, 0)

	for _, cidrEntry := range e {
		ipAddr, _, err := net.ParseCIDR(cidrEntry)
		if err != nil {
			log.Printf("CIDR parsing for CIDR entry %q failed: %s", cidrEntry, err)
			continue
		}

		_, err = f.execPfCtl("-t", t, "-T", "add", ipAddr.String())
		if err != nil {
			errArray = append(errArray, err)
		}
	}

	if len(errArray) > 0 {
		return fmt.Errorf("One or more errors occured adding IP(s) to table: %#v", errArray)
	}

	return nil
}

// AddToTableIP adds one or more IP entries to a pf radix table.
// Returns error on parsing failures or execution issues
func (f *Firewall) AddToTableIP(t string, e ...string) error {
	errArray := make([]error, 0)

	for _, ipEntry := range e {
		ipAddr := net.ParseIP(ipEntry)
		if ipAddr == nil {
			log.Printf("IP address parsing for IP entry %q failed", ipEntry)
			continue
		}

		_, err := f.execPfCtl("-t", t, "-T", "add", ipAddr.String())
		if err != nil {
			errArray = append(errArray, err)
		}
	}

	if len(errArray) > 0 {
		return fmt.Errorf("One or more errors occured adding IP(s) to table: %#v", errArray)
	}

	return nil
}
