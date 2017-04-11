/*
Copyright 2017 The Camlistore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"os"

	"camlistore.org/pkg/cmdmain"
)

type sharedCmd struct {
	*searchCmd

	transitive bool
}

func init() {
	cmdmain.RegisterCommand("shared", func(flags *flag.FlagSet) cmdmain.CommandRunner {
		cmd := &sharedCmd{
			searchCmd: &searchCmd{},
		}
		flags.StringVar(&cmd.searchCmd.server, "server", "", "Server to search. "+serverFlagHelp)
		flags.BoolVar(&cmd.transitive, "transitive", false, "When listing, if -transitive, only lists the transitive share claims.")
		return cmd
	})
}

func (c *sharedCmd) Describe() string {
	return "If the given argument is shared, returns the claim(s) responsible for its sharing. If no argument, lists share claims."
}

func (c *sharedCmd) Usage() {
	fmt.Fprintf(os.Stderr, "Usage: camtool [globalopts] shared [listopts] fileRef\n")
}

func (c *sharedCmd) Examples() []string {
	return nil
}

func (c *sharedCmd) RunCommand(args []string) error {
	if len(args) > 1 {
		return cmdmain.UsageError("command requires one fileRef argument, or no argument.")
	}
	if len(args) != 0 {
		constraint := fmt.Sprintf(`{"logical": {"a": {"claim":{"share":{"target": "%s", "any": true}}}, "b": {"claim":{"share":{"targetInSet": {"dir": {"recursiveContains": {"blobRefPrefix": "%s"}}}, "any": true}}}, "op": "or"}}`, args[0], args[0])
		return c.searchCmd.RunCommand([]string{constraint})
	}
	var constraint string
	if c.transitive {
		constraint = `{"claim":{"share":{"transitive": true}}}`
	} else {
		constraint = `{"claim":{"share":{"any": true}}}`
	}
	return c.searchCmd.RunCommand([]string{constraint})
}
