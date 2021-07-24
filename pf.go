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
const VERSION = "0.1.0"

const (
	// Protocols
	ProtocolTcp PfProtocol = iota
	ProtocolUdp
	ProtocolIcmp
	ProtocolIcmpv6

	// Directions
	DirectionIn PfDirection = iota
	DirectionOut

	// Actions
	ActionPass PfAction = iota
	ActionBlock

	// Address families
	AdressFamilyInet PfAddrFam = iota
	AdressFamilyInetv6
)

type PfAction int
type PfAddrFam int
type PfDirection int
type PfProtocol int

type Firewall struct {
	ControlCmdPath string
	IoDev          string
}

func NewFirewall(p ...string) (Firewall, error) {
	fwObj := Firewall{
		IoDev: "/dev/pf",
	}
	if len(p) == 1 {
		fwObj.ControlCmdPath = p[0]
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

// CommitAnchor takes all commited RuleSet of the current Anchor and commits them as ruleset to the
// pfctl anchor
func (f *Firewall) CommitAnchor(a *Anchor) error {
	var byteBuffer bytes.Buffer
	var err error
	ruleSet := a.RuleSet.RulesString() + "\n"

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

// execPfCtl executes the pfctl command with a given list of arguments and returns
// a string array with the output or an error if the execution failed
func (f *Firewall) execPfCtl(a ...string) ([]string, error) {
	stdoutArray := make([]string, 0)

	// Let's limit the execution time
	execCtx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	// Initialize the execution
	execCmd := exec.CommandContext(execCtx, f.ControlCmdPath)
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
func parseIP(i string, m []string) net.IPNet {
	ipAddr := net.ParseIP(i)
	netMask := net.IPv4Mask(255, 255, 255, 255)
	if len(m) == 1 {
		ipMask, err := fullNetmaskToBytes(m[0])
		if err == nil {
			netMask = ipMask
		}
	}
	return net.IPNet{IP: ipAddr, Mask: netMask}
}
