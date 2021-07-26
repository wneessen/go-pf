// +build !windows,!plan9,!linux

package pf

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/wneessen/go-fileperm"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// VERSION of go-pf, follows Semantic Versioning. (http://semver.org/)
const VERSION = "0.1.2"

// Constants that reflect different Protocols, Directions, Actions, etc.
const (
	// Protocols
	ProtocolTcp PfProtocol = iota
	ProtocolUdp
	ProtocolIcmp
	ProtocolIcmpv6
	ProtocolUnknown

	// Directions
	DirectionIn PfDirection = iota
	DirectionOut
	DirectionUnknown

	// Actions
	ActionPass PfAction = iota
	ActionBlock
	ActionUnknown

	// Address families
	AdressFamilyInet PfAddrFam = iota
	AdressFamilyInetv6
)

// PfAction represents a action in the pf firewall ruleset (i. e. block or pass)
type PfAction int

// PfAddrFam represents an address family in the pf firewall ruleset (i. e. inet or inet6)
type PfAddrFam int

// PfDirection represents the direction of data flow in the pf firewall ruleset (i. e. in or out)
type PfDirection int

// PfProtocol represents a protocol in the pf firewall ruleset (i. e. tcp or udp)
type PfProtocol int

// Firewall is the main Pf struct
type Firewall struct {
	ControlCmdPath string
	IoDev          string
}

// NewFirewall returns a new Firewall struct. It returns an error if the current process is not able
// to execute the pfctl binary or is not able to read/write the /dev/pf interface
func NewFirewall() (Firewall, error) {
	return newFwObj("/sbin/pfctl", "/dev/pf")
}

// NewFirewallCustom returns a new Firewall struct. It takes two argument strings for the path to a
// non-default pfctl binary and/or /dev/pf path. It returns an error if the current process is not able
// to execute the pfctl binary or is not able to read/write the /dev/pf interface
func NewFirewallCustom(c string, i string) (Firewall, error) {
	return newFwObj(c, i)
}

// ParseAction converts a given string to a PfAction (if known)
func ParseAction(a string) PfAction {
	switch strings.ToLower(a) {
	case "block":
		return ActionBlock
	case "pass":
		return ActionPass
	default:
		return ActionUnknown
	}
}

// ParseDirection converts a given string to a PfDirection (if known)
func ParseDirection(d string) PfDirection {
	switch strings.ToLower(d) {
	case "in":
		return DirectionIn
	case "out":
		return DirectionOut
	default:
		return DirectionUnknown
	}
}

// ParseProtocol converts a given string to a PfProtocol (if known)
func ParseProtocol(p string) PfProtocol {
	switch strings.ToLower(p) {
	case "tcp":
		return ProtocolTcp
	case "udp":
		return ProtocolUdp
	case "icmp":
		return ProtocolIcmp
	case "icmp6":
		return ProtocolIcmpv6
	default:
		return ProtocolUnknown
	}
}

// Enabled returns true if the packet filter is enabled
func (f *Firewall) Enabled() bool {
	statOutput, err := f.execPfCtl("-s", "Running")
	if err != nil {
		return false
	}
	if statOutput[0] == "Enabled" {
		return true
	}
	return false
}

// Enable enables the firewall
func (f *Firewall) Enable() error {
	if f.Enabled() {
		return nil
	}
	_, err := f.execPfCtl("-e")
	if err != nil {
		return err
	}
	return nil
}

// Disable disables the firewall
func (f *Firewall) Disable() error {
	if !f.Enabled() {
		return nil
	}
	_, err := f.execPfCtl("-d")
	if err != nil {
		return err
	}
	return nil
}

// CommitAnchor takes all committed RuleSet a given Anchor and commits them as ruleset to the pfctl anchor
func (f *Firewall) CommitAnchor(a *Anchor) error {
	var byteBuffer bytes.Buffer
	var err error
	ruleSet := a.ruleSet.RulesString() + "\n"

	_, err = byteBuffer.Write([]byte(ruleSet))
	if err != nil {
		return err
	}

	_, err = f.execPfCtlStdin(byteBuffer, "-a", a.Name, "-f", "-", "-v")
	if err != nil {
		return err
	}

	return nil
}

// FlushAnchor flushes all rules of a given Anchor
func (f *Firewall) FlushAnchor(a *Anchor) error {
	_, err := f.execPfCtl("-a", a.Name, "-F", "rules")
	if err != nil {
		return err
	}

	return nil
}

// newFwObj returns a new Firewall struct. It pre-fills the object with required data and takes
// a optional argument strings for the path to a non-default pfctl binary and/or /dev/pf path. It returns
//an error if the current process is not able to execute the pfctl binary or is not able to read/write the
// /dev/pf interface
func newFwObj(c string, i string) (Firewall, error) {
	if c == "" {
		return Firewall{}, fmt.Errorf("No pfctl path given.")
	}
	if i == "" {
		return Firewall{}, fmt.Errorf("No iodev path given.")
	}
	fwObj := Firewall{
		ControlCmdPath: c,
		IoDev:          i,
	}

	// Validate that ControlCmdPath and IoDev is working and permissions are given
	ctlCmdFilePerm, err := fileperm.New(fwObj.ControlCmdPath)
	if err != nil {
		return fwObj, err
	}
	if ok := ctlCmdFilePerm.UserExecutable(); !ok {
		return fwObj, fmt.Errorf("%s is not executable", fwObj.ControlCmdPath)
	}
	ioDevFilePerm, err := fileperm.New(fwObj.IoDev)
	if err != nil {
		return fwObj, err
	}
	if ok := ioDevFilePerm.UserWriteReadable(); !ok {
		return fwObj, fmt.Errorf("%s is not read-/writable", fwObj.IoDev)
	}

	return fwObj, nil
}

// execPfCtl executes the pfctl command with a given list of arguments and returns
// a string array with the output or an error if the execution failed
func (f *Firewall) execPfCtl(a ...string) ([]string, error) {
	stdoutArray := make([]string, 0)

	// Let's limit the execution time
	execCtx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	// Initialize the execution
	execCmd := exec.CommandContext(execCtx, f.ControlCmdPath)
	execCmd.Args = append(execCmd.Args, "-q")
	execCmd.Args = append(execCmd.Args, a...)

	// Let's also read stderr
	var errBuf bytes.Buffer
	execCmd.Stderr = &errBuf

	// Stdout shall be piped to bufio
	stdOutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		return stdoutArray, err
	}
	stdOutScanner := bufio.NewScanner(stdOutPipe)

	// Start the execution
	if err := execCmd.Start(); err != nil {
		return stdoutArray, err
	}

	// Read the stdout buffer
	for stdOutScanner.Scan() {
		stdoutArray = append(stdoutArray, stdOutScanner.Text())
	}
	if err := stdOutScanner.Err(); err != nil {
		return stdoutArray, err
	}

	// Wait for completion or cancellation
	if err := execCmd.Wait(); err != nil {
		return stdoutArray, fmt.Errorf("command execution failed: %s => %s", err.Error(), errBuf.String())
	}

	return stdoutArray, nil
}

// execPfCtlStdin executes the pfctl command with a given list of arguments and pipes a given
// byte buffer to it as Stdin. It returns a string array with the output or an error if the
// execution failed
func (f *Firewall) execPfCtlStdin(si bytes.Buffer, a ...string) ([]string, error) {
	stdoutArray := make([]string, 0)

	// Let's limit the execution time
	execCtx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	// Initialize the execution
	execCmd := exec.CommandContext(execCtx, f.ControlCmdPath)
	execCmd.Args = append(execCmd.Args, "-q")
	execCmd.Args = append(execCmd.Args, a...)

	// Let's also read stderr
	var errBuf bytes.Buffer
	execCmd.Stderr = &errBuf

	// Stdout shall be piped to bufio
	stdOutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		return stdoutArray, err
	}
	stdOutScanner := bufio.NewScanner(stdOutPipe)

	// Stdin shall be piped with si
	stdinPipe, err := execCmd.StdinPipe()
	if err != nil {
		return stdoutArray, err
	}

	// Start the execution
	if err := execCmd.Start(); err != nil {
		return stdoutArray, err
	}

	// Write to stdin and close it
	_, err = stdinPipe.Write(si.Bytes())
	if err != nil {
		return stdoutArray, err
	}
	if err := stdinPipe.Close(); err != nil {
		return stdoutArray, err
	}

	// Read the stdout buffer
	for stdOutScanner.Scan() {
		stdoutArray = append(stdoutArray, stdOutScanner.Text())
	}
	if err := stdOutScanner.Err(); err != nil {
		return stdoutArray, err
	}

	// Wait for completion or cancellation
	if err := execCmd.Wait(); err != nil {
		return stdoutArray, fmt.Errorf("command execution failed: %s => %s", err.Error(), errBuf.String())
	}

	return stdoutArray, nil
}

// fullNetmaskToBytes converts a full 4-tuple netmask into CIDR notation
func fullNetmaskToBytes(m string) (net.IPMask, error) {
	tBytes := make([]byte, 0)
	tupArray := strings.SplitN(m, ".", 4)
	for _, s := range tupArray {
		tInt, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return net.IPMask{}, err
		}
		if tInt >= 0 && tInt <= 255 {
			tBytes = append(tBytes, byte(tInt))
		}
	}

	if len(tBytes) == 4 {
		ipMask := net.IPv4Mask(tBytes[0], tBytes[1], tBytes[2], tBytes[3])
		return ipMask, nil
	}
	return net.IPMask{}, fmt.Errorf("Netmask conversion failed.")
}

// parseIP parses a given IP address with an optional netmask
func parseIP(i string, m []string) *net.IPNet {
	ipAddr := net.ParseIP(i)
	netMask := net.IPv4Mask(255, 255, 255, 255)
	if len(m) == 1 {
		ipMask, err := fullNetmaskToBytes(m[0])
		if err == nil {
			netMask = ipMask
		}
	}
	return &net.IPNet{IP: ipAddr, Mask: netMask}
}
