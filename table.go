// +build !windows,!plan9,!linux

package pf

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// GetTables returns a string array of currently configured firewall table
func (f *Firewall) GetTables() ([]string, error) {
	return f.execPfCtl("-s", "Tables")
}

// AddToTableCIDR adds one or more CIDR entries to a pf radix table.
// Returns error on parsing failures or execution issues
func (f *Firewall) AddToTableCIDR(t string, e ...string) error {
	errArray := make([]string, 0)

	for _, cidrEntry := range e {
		ipAddr, _, err := net.ParseCIDR(cidrEntry)
		if err != nil {
			log.Printf("CIDR parsing for CIDR entry %q failed: %s", cidrEntry, err)
			continue
		}

		_, err = f.execPfCtl("-t", t, "-T", "add", ipAddr.String())
		if err != nil {
			errArray = append(errArray, err.Error())
		}
	}

	if len(errArray) > 0 {
		return fmt.Errorf("One or more errors occurred adding IP(s) to table: %s",
			strings.Join(errArray, ", "))
	}

	return nil
}

// AddToTableIP adds one or more IP entries to a pf radix table.
// Returns error on parsing failures or execution issues
func (f *Firewall) AddToTableIP(t string, e ...string) error {
	errArray := make([]string, 0)

	for _, ipEntry := range e {
		ipAddr := net.ParseIP(ipEntry)
		if ipAddr == nil {
			log.Printf("IP address parsing for IP entry %q failed", ipEntry)
			continue
		}

		_, err := f.execPfCtl("-t", t, "-T", "add", ipAddr.String())
		if err != nil {
			errArray = append(errArray, err.Error())
		}
	}

	if len(errArray) > 0 {
		return fmt.Errorf("One or more errors occurred adding IP(s) to table: %s",
			strings.Join(errArray, ", "))
	}

	return nil
}

// RemoveFromTableCIDR adds one or more CIDR entries to a pf radix table.
// Returns error on parsing failures or execution issues
func (f *Firewall) RemoveFromTableCIDR(t string, e ...string) error {
	errArray := make([]string, 0)

	for _, cidrEntry := range e {
		ipAddr, _, err := net.ParseCIDR(cidrEntry)
		if err != nil {
			log.Printf("CIDR parsing for CIDR entry %q failed: %s", cidrEntry, err)
			continue
		}

		_, err = f.execPfCtl("-t", t, "-T", "delete", ipAddr.String())
		if err != nil {
			errArray = append(errArray, err.Error())
		}
	}

	if len(errArray) > 0 {
		return fmt.Errorf("One or more errors occurred removing IP(s) from table: %s",
			strings.Join(errArray, ", "))
	}

	return nil
}

// RemoveFromTableIP adds one or more IP entries to a pf radix table.
// Returns error on parsing failures or execution issues
func (f *Firewall) RemoveFromTableIP(t string, e ...string) error {
	errArray := make([]string, 0)

	for _, ipEntry := range e {
		ipAddr := net.ParseIP(ipEntry)
		if ipAddr == nil {
			log.Printf("IP address parsing for IP entry %q failed", ipEntry)
			continue
		}

		_, err := f.execPfCtl("-t", t, "-T", "delete", ipAddr.String())
		if err != nil {
			errArray = append(errArray, err.Error())
		}
	}

	if len(errArray) > 0 {
		return fmt.Errorf("One or more errors occurred removing IP(s) from table: %s",
			strings.Join(errArray, ", "))
	}

	return nil
}
