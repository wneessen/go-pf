package pf

import (
	"testing"
)

// TestNewFirewall tests the NewFirewall function
func TestNewFirewall(t *testing.T) {
	_, err := NewFirewall()
	if err != nil {
		t.Errorf("Could not create firewall object: %s", err)
	}
	_, err = NewFirewall()
	if err != nil {
		t.Errorf("Could not create firewall object: %s", err)
	}
	_, err = NewFirewallCustom("/does/not/exist", "/does/also/not/exist")
	if err == nil {
		t.Errorf("Could not create firewall object: %s", err)
	}
}

func TestFirewall_EnableDisable(t *testing.T) {
	f, err := NewFirewall()
	if err != nil {
		t.Errorf("Could not create firewall object: %s", err)
	}
	if f.Enabled() {
		if err := f.Disable(); err != nil {
			t.Errorf("Failed to disable firewall: %s", err)
		}
		if err := f.Enable(); err != nil {
			t.Errorf("Failed to enable firewall: %s", err)
		}
	}
	if !f.Enabled() {
		if err := f.Enable(); err != nil {
			t.Errorf("Failed to enable firewall: %s", err)
		}
		if err := f.Disable(); err != nil {
			t.Errorf("Failed to disable firewall: %s", err)
		}
	}
}

// TestFirewall_NewAnchor tests the creation of a new anchor object on the FW object
func TestFirewall_NewAnchor(t *testing.T) {
	f, err := NewFirewall()
	if err != nil {
		t.Errorf("Could not create firewall object: %s", err)
	}
	a := f.NewAnchor("testanchor")
	if a.Name != "testanchor" {
		t.Errorf("Anchor is not named as expected. Expected 'testanchor', got '%s'", a.Name)
	}
}

// TestFirewall_GetTables tests the GetTables method on the FW object
func TestFirewall_GetTables(t *testing.T) {
	f, err := NewFirewall()
	if err != nil {
		t.Errorf("Could not create firewall object: %s", err)
	}
	_, err = f.GetTables()
	if err != nil {
		t.Errorf("Failed to get list of tables: %s", err)
	}
}

func TestFirewall_AddToTableIP(t *testing.T) {
	testTable := []struct {
		testName   string
		tableName  string
		ipAddr     string
		shouldFail bool
	}{
		{"Valid IP", "testtable", "123.123.123.123", false},
	}
	f, err := NewFirewall()
	if err != nil {
		t.Errorf("Could not create firewall object: %s", err)
	}

	for _, testCase := range testTable {
		t.Run(testCase.testName, func(t *testing.T) {
			if err := f.AddToTableIP(testCase.tableName, testCase.ipAddr); err != nil {
				if !testCase.shouldFail {
					t.Errorf("Adding IP address to table failed: %s", err)
				}
			}
		})
	}

}
