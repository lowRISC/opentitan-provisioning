// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// This file contains various test-support details for the pk11 test,
// such as standing up a SoftHSMv2-based HSM environment and associated
// tokens.

package test_support

import (
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"github.com/lowRISC/opentitan-provisioning/third_party/softhsm2/test_config"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
)

const (
	SecOffPin = "sec-off-pin"
	UserPin   = "cryptoki"
)

var (
	// NOTE: These are not initialized until the first call to GetMod(),
	// so that it is not called until the first test starts.
	tokMap      map[string]int
	mod         *pk11.Mod
	startupFlag sync.Once
)

// Check checks that e is not nil and fails the test if it is.
func Check(t *testing.T, e error) {
	t.Helper()

	if e != nil {
		t.Fatal(e)
	}
}

// makeHash computes a hash of message.
func MakeHash(hash crypto.Hash, message []byte) []byte {
	hasher := hash.New()
	for len(message) > 0 {
		n, err := hasher.Write(message)
		if err != nil {
			panic(err)
		}
		message = message[n:]
	}

	return hasher.Sum(nil)
}

// Plugin returns a path to the SoftHSM PKCS#11 plugin library.
func Plugin() string {
	path, err := bazel.Runfile("softhsm2/lib/softhsm/libsofthsm2.so")
	if err != nil {
		panic(err)
	}
	return path
}

// GetMod gets a PKCS#11 module that has been properly stood up for testing.
func GetMod() *pk11.Mod {
	startupFlag.Do(func() {
		// This order is critical. libsofthsm2.so really doesn't seem to like it when
		// tokens are created after it's been loaded, so we need to pre-generate all of
		// them before we do anything else.
		fmt.Println("*** creating SoftHSM tokens...")
		tokMap = makeTokens()
		fmt.Println("*** loading SoftHSM...")
		mod = loadSoftHSM()
		fmt.Println("*** loading complete!")
		// Uncomment this to see that loading is working correctly; it is
		// too noisy for normal use.
		// fmt.Println(mod.Dump())
	})
	return mod
}

// GetSlot returns the index of t's dedicated token.
func GetSlot(t *testing.T) int {
	tokSlot, ok := tokMap[t.Name()]
	if !ok {
		t.Fatal("missing SoftHSM token? this is a test harness bug")
	}
	return tokSlot
}

// GetSession opens a session with t's dedicated token.
func GetSession(t *testing.T) *pk11.Session {
	t.Helper()
	GetMod()

	tokSlot, ok := tokMap[t.Name()]
	if !ok {
		t.Fatal("missing SoftHSM token? this is a test harness bug")
	}

	toks, err := mod.Tokens()
	if err != nil {
		t.Fatal(err)
	}

	s, err := toks[tokSlot].OpenSession()
	if err != nil {
		t.Fatal(err)
	}

	return s
}

// loadSoftHSM finds the Bazel-provided SoftHSM plugin and loads it.
func loadSoftHSM() *pk11.Mod {
	if tokMap == nil {
		return nil
	}

	m, err := pk11.Load(Plugin())
	if err != nil {
		panic(err)
	}

	return m
}

// discoverTestNames discovers the names of all tests via self-exec.
func discoverTestNames() []string {
	const SelfExecEnvVar = "OT_PROV_PK11_SELF_EXEC"
	if _, ok := os.LookupEnv(SelfExecEnvVar); ok {
		// We're in a self-exec copy of the test binary. Do not self-exec again to
		// avoid a forkbomb!
		return nil
	}

	self, err := os.Executable()
	if err != nil {
		panic(err)
	}

	cmd := exec.Command(self, "-test.list=.")

	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=yes", SelfExecEnvVar))
	cmd.Run()

	return strings.Split(stdout.String(), "\n")
}

// makeTokens shells out to softhsm2-util to create one token for each test
// case to use separately.
func makeTokens() map[string]int {
	softhsmPath := os.ExpandEnv("$TEST_TMPDIR/softhsm2-") + strconv.Itoa(os.Getpid())
	configPath, err := test_config.MakeSandboxIn(softhsmPath)
	if err != nil {
		panic(err)
	}
	os.Setenv(test_config.EnvVar, configPath)

	softHSMUtilPath := os.ExpandEnv("$TEST_SRCDIR/softhsm2/softhsm2/bin/softhsm2-util")

	toks := map[string]int{}
	plugin := Plugin()
	for i, test := range discoverTestNames() {
		cmd := exec.Command(
			softHSMUtilPath,
			"--init-token",
			"--so-pin", SecOffPin,
			"--pin", UserPin,
			"--slot", strconv.Itoa(i),
			"--label", test,
			"--module", plugin,
		)

		var stdout strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stdout

		if err := cmd.Run(); err != nil {
			panic(fmt.Sprintf("could not run softhsm2-util: %s; stdout:\n%s", err, stdout.String()))
		}
		toks[test] = i
	}

	return toks
}
