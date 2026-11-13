// Copyright (C) 2021  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cli

import (
	"fmt"
	"os"
	"strings"
)

var binaryName = "mieru"

type matchProcessor struct {
	matches   []string
	validator func([]string) error
	callback  func([]string) error
}

var hooks = make([]matchProcessor, 0)

func RegisterCallback(exactMatches []string, validator func([]string) error, callback func([]string) error) {
	hooks = append(hooks, matchProcessor{
		matches:   exactMatches,
		validator: validator,
		callback:  callback,
	})
}

func ParseAndExecute() error {
	args := os.Args
	found := false
	for _, hook := range hooks {
		if !doExactMatch(args, hook.matches) {
			continue
		}
		found = true
		if err := hook.validator(args); err != nil {
			return err
		}
		err := hook.callback(args)
		if err != nil {
			return err
		}
		break
	}
	if !found {
		cmd := strings.Join(args, " ")
		return fmt.Errorf("%q is not a valid command. Run \"%s help\" to get the list of supported commands", cmd, binaryName)
	}
	return nil
}

func doExactMatch(input, want []string) bool {
	if len(input) < len(want) {
		return false
	}
	for i := 0; i < len(want); i++ {
		if want[i] != "" && input[i] != want[i] {
			return false
		}
	}
	return true
}

func unexpectedArgsError(args []string, length int) error {
	if len(args) > length {
		prefix := strings.Join(args[:length], " ")
		unexpected := strings.Join(args[length:], " ")
		return fmt.Errorf("unexpected arguments %q after %q", unexpected, prefix)
	}
	return nil
}
