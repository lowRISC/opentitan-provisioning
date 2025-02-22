// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package commands defines commands that can be executed by the pk11 tool's
// REPL.
package commands

import (
	"crypto"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/pk11/tool/lex"
)

// Stringify generates a string representation of various values that commands
// may return.
func Stringify(v any) (string, error) {
	switch v := v.(type) {
	case nil:
		return "", nil
	case []byte:
		return fmt.Sprintf(`h"%x"`, v), nil
	case pk11.Object:
		uid, err := v.UID()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf(`obj:h"%x"`, uid), nil
	default:
		panic("unknown type")
	}
}

type ArgTy int

const (
	ArgBytes ArgTy = 1 << iota
	ArgBool
	ArgInt
	ArgObj
	ArgKey
	ArgPublic
	ArgPrivate
	ArgSecret

	ArgOptional
	ArgTokens
)

// Command wraps the function that executes a command with some auxiliary data.
type Command struct {
	// The name of the command, for runtime lookup.
	Name string
	// The usage of the command for display in help messages.
	Usage string
	// A description of the command for display in help messages.
	Help string
	// Valid values for the number of arguments to pass, or nil if
	// the command checks this itself.
	Argc []int
	// Expected argument types for this command.
	Args []ArgTy
	// Whether a session must be active to use this command.
	NeedsSession bool
	// The actual execution function for the command.
	Run func([]any, *State) (any, error)
}

// State represents the collective state of the interpreter.
type State struct {
	m    *pk11.Mod
	s    *pk11.Session
	vars map[string]any
	cmds map[string]*Command
}

// New creates a new interpreter to run commands on, wrapping the given
// PKCS#11 module.
func New(modPath string) (*State, error) {
	m, err := offload(fmt.Sprintf("loading PKCS#11 module %q", modPath), func() (any, error) {
		return pk11.Load(modPath)
	})
	if err != nil {
		return nil, err
	}

	return fromMod(m.(*pk11.Mod)), nil
}

func fromMod(m *pk11.Mod) *State {
	s := &State{
		m:    m,
		vars: make(map[string]any),
		cmds: make(map[string]*Command),
	}

	s.basicCommands()
	s.pk11Commands()
	s.cryptoCommands()
	s.aesCommands()
	s.ecdsaCommands()
	s.rsaCommands()

	return s
}

// Define defines a new command.
func (s *State) Define(c *Command) {
	s.cmds[c.Name] = c
}

type ty int

const (
	tyBytes = iota
	tyObj
	tyKey
	tyPub
	tyPriv
	tySec
)

func (s *State) resolve(tok lex.Token, ty ArgTy) (any, error) {
	var value any
	switch tok := tok.Value.(type) {
	case lex.Str:
		value = []byte(string(tok))
	case lex.Int:
		value = int64(tok)
	case lex.Var:
		v, ok := s.vars[string(tok)]
		if !ok {
			return nil, fmt.Errorf("no variable %q", string(tok))
		}
		value = v
	default:
		return nil, fmt.Errorf("bad token type %s; this is a bug", reflect.TypeOf(tok))
	}

	var tries []string

	if ty&ArgBool != 0 {
		str, ok := value.([]byte)
		if !ok {
			tries = append(tries, "boolean")
		} else if b, ok := parseBool(string(str)); ok {
			return b, nil
		}
		tries = append(tries, "boolean")
	}
	if ty&ArgBytes != 0 {
		if _, ok := value.([]byte); ok {
			return value, nil
		}
		tries = append(tries, "byte array")
	}
	if ty&ArgInt != 0 {
		if _, ok := value.(int64); ok {
			return value, nil
		}
		tries = append(tries, "integer")
	}
	if ty&ArgObj != 0 {
		if _, ok := value.(pk11.Object); ok {
			return value, nil
		}
		tries = append(tries, "PKCS#11 object")
	}
	if ty&ArgKey != 0 {
		if _, ok := value.(pk11.Key); ok {
			return value, nil
		}
		tries = append(tries, "key object")
	}
	if ty&ArgPublic != 0 {
		if _, ok := value.(pk11.PublicKey); ok {
			return value, nil
		}
		tries = append(tries, "public key object")
	}
	if ty&ArgPrivate != 0 {
		if _, ok := value.(pk11.PrivateKey); ok {
			return value, nil
		}
		tries = append(tries, "private key object")
	}
	if ty&ArgSecret != 0 {
		if _, ok := value.(pk11.SecretKey); ok {
			return value, nil
		}
		tries = append(tries, "secret key object")
	}

	return nil, fmt.Errorf("expected `%s` to be one of: %s; was actually %s", tok, strings.Join(tries, ", "), reflect.TypeOf(value))
}

// Run executes the command described by the given sequence of lexer tokens.
func (s *State) Run(args ...lex.Token) (any, error) {
	defer func(args []lex.Token) {
		// Add context to any panic on the way out.
		if r := recover(); r != nil {
			var s strings.Builder
			for i, token := range args {
				if i != 0 {
					fmt.Fprint(&s, " ")
				}
				fmt.Fprint(&s, token.Text)
			}
			panic(fmt.Sprintf("panicked while executing `%s`: %v", s.String(), r))
		}
	}(args)

	if len(args) == 0 {
		return nil, nil
	}

	name, err := s.resolve(args[0], ArgBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse command name: %s", err)
	}
	cmd, ok := s.cmds[string(name.([]byte))]
	if !ok {
		return nil, fmt.Errorf("unknown command %q", args[0])
	}

	if cmd.NeedsSession && s.s == nil {
		return nil, fmt.Errorf("no active session right now")
	}

	args = args[1:]
	if len(args) > len(cmd.Args) && cmd.Args[len(cmd.Args)-1]&ArgTokens == 0 {
		fmt.Errorf("expected at most %d arguments", len(cmd.Args))
	}
	argVals := make([]any, len(cmd.Args))
	for i, ty := range cmd.Args {
		if ty&ArgTokens != 0 {
			argVals[i] = args[i:]
			break
		}

		if len(args) <= i {
			if ty&ArgOptional != 0 {
				break
			}
			return nil, fmt.Errorf("expected at least %d arguments", i)
		}

		v, err := s.resolve(args[i], ty)
		if err != nil {
			return nil, err
		}
		argVals[i] = v
	}

	return cmd.Run(argVals, s)
}

// Interpret peels off enough tokens from lexer to build a complete command, and
// executes it with Run.
//
// Returns the tokens parsed (including the terminator), as well as the results of
// Run. Interpret will consume tokens until it hits a terminator or too many errors
// are raised as a result of parsing.
func (s *State) Interpret(lexer *lex.Lex) (tokens []lex.Token, val any, errs []error) {
	const maxErrors = 100

	for {
		tok, err := lexer.Next()
		if err != nil {
			errs = append(errs, err)
			if len(errs) > maxErrors {
				return
			}
		}

		tokens = append(tokens, tok)
		switch tok.Value.(type) {
		case lex.End, lex.EOF:
			if len(errs) != 0 {
				return
			}

			var err error
			val, err = s.Run(tokens[:len(tokens)-1]...)
			if err != nil {
				errs = append(errs, err)
			}
			return
		}
	}
}

func offload(banner string, f func() (any, error)) (any, error) {
	fmt.Fprint(os.Stderr, banner)

	ch := make(chan any)
	var err error
	go func() {
		var out any
		out, err = f()
		ch <- out
	}()

	ticker := time.NewTicker(time.Second / 2)
	for {
		select {
		case <-ticker.C:
			fmt.Fprint(os.Stderr, ".")
		case out := <-ch:
			fmt.Fprintln(os.Stderr)
			return out, err
		}
	}
}

// parseHash converts a user-provided name into a crypto.Hash.
func parseHash(name string) (hash crypto.Hash, err error) {
	switch strings.ToLower(name) {
	case "sha256", "sha-256":
		hash = crypto.SHA256
	case "sha384", "sha-384":
		hash = crypto.SHA384
	case "sha512", "sha-512":
		hash = crypto.SHA512
	default:
		err = fmt.Errorf("unknown hash: %s", name)
	}
	return
}

// parseBool converts a user-provided string like true, yes, or on into a bool.
func parseBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "true", "t", "yes", "y", "on":
		return true, true
	case "false", "f", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}
