package main

import (
	"flag"
	"strings"
)

// The standard library's flag package stops parsing at the first positional
// argument, so "plainq send <queue-id> -message=hi" silently drops -message:
// the flag lands in Args() and nothing ever reads it. That ordering is the one
// people and agents reach for first, and a silently ignored -ack or -force is
// the kind of surprise that costs data.
//
// normalizeArgs removes the trap by rewriting the argument list before it is
// parsed, so flags may appear anywhere after the command name.

// normalizeArgs reorders args so that every flag precedes every positional
// argument, leaving the command path in front. args excludes the program name.
//
// Rewriting requires knowing which flags consume the following token as their
// value, which is why the command tree — and therefore each command's live
// FlagSet — has to be resolved first. Unknown flags are left alone so that the
// flag package still reports them.
func normalizeArgs(root *commandSpec, args []string) []string {
	if root == nil {
		return args
	}

	resolved := resolveCommand(root, args)

	// A command that still has subcommands takes no positional arguments of its
	// own, so a leftover word is a misspelled command name. Reordering around it
	// would only obscure the error, so hand the arguments back untouched and let
	// the command tree report what it does not recognize.
	if len(resolved.command.Subcommands) > 0 && len(resolved.rest) > 0 && !startsWithDash(resolved.rest[0]) {
		return args
	}

	split := splitArgs(resolved.command, resolved.rest)

	normalized := make([]string, 0, len(args)+1)
	normalized = append(normalized, resolved.path...)
	normalized = append(normalized, split.flags...)

	// "--" has to be re-inserted whenever a positional could be mistaken for a
	// flag, otherwise moving it behind the flags would change how it parses.
	if len(split.positionals) > 0 && (split.terminated || startsWithDash(split.positionals[0])) {
		normalized = append(normalized, "--")
	}

	normalized = append(normalized, split.positionals...)

	return normalized
}

// resolvedCommand is a command line matched against the command tree: the
// command that will run, the words that selected it, and what is left for that
// command to parse.
type resolvedCommand struct {
	command *commandSpec
	path    []string
	rest    []string
}

// resolveCommand walks the leading non-flag tokens of args down the command
// tree.
//
// The walk stops at the first flag because a flag can only ever belong to a
// command that has already been named: a group like "plainq cluster" defines no
// flags of its own, so "plainq cluster -json status" cannot parse regardless of
// how the arguments are ordered.
func resolveCommand(root *commandSpec, args []string) resolvedCommand {
	resolved := resolvedCommand{
		command: root,
		path:    make([]string, 0, len(args)),
	}

	for i, arg := range args {
		if startsWithDash(arg) {
			resolved.rest = args[i:]

			return resolved
		}

		sub := resolved.command.lookup(arg)
		if sub == nil {
			resolved.rest = args[i:]

			return resolved
		}

		resolved.command = sub

		resolved.path = append(resolved.path, arg)
	}

	return resolved
}

// splitCommandArgs is one command's arguments separated into the flags it will
// parse and the positionals it will read, plus whether an explicit "--"
// terminator was seen.
type splitCommandArgs struct {
	flags       []string
	positionals []string
	terminated  bool
}

// splitArgs separates args into flags (with their values) and positionals for
// the given command.
func splitArgs(command *commandSpec, args []string) splitCommandArgs {
	var split splitCommandArgs

	set := command.command().Flags().FlagSet

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Everything past "--" is positional by definition, however it looks.
		if arg == "--" {
			split.positionals = append(split.positionals, args[i+1:]...)
			split.terminated = true

			return split
		}

		if !startsWithDash(arg) {
			split.positionals = append(split.positionals, arg)

			continue
		}

		split.flags = append(split.flags, arg)

		// "-flag=value" carries its value in the same token; only the separated
		// form needs the next token pulled along with it. The name is unwrapped
		// the way the flag package does it: at most two leading dashes.
		name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		if strings.Contains(name, "=") {
			continue
		}

		if takesValue(set, name) && i+1 < len(args) {
			i++

			split.flags = append(split.flags, args[i])
		}
	}

	return split
}

// takesValue reports whether the named flag consumes the next argument. Unknown
// flags and boolean flags do not: an unknown flag is about to be rejected by
// the flag package, and swallowing the token after it would turn a clear
// "flag provided but not defined" into a confusing missing-argument error.
func takesValue(set *flag.FlagSet, name string) bool {
	if set == nil {
		return false
	}

	found := set.Lookup(name)
	if found == nil {
		return false
	}

	boolFlag, ok := found.Value.(interface{ IsBoolFlag() bool })

	return !ok || !boolFlag.IsBoolFlag()
}

// startsWithDash reports whether arg is written like a flag. A lone "-" is not:
// it is the conventional name for standard input and is passed as a value.
func startsWithDash(arg string) bool {
	return len(arg) > 1 && arg[0] == '-'
}
