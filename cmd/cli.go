package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/heartwilltell/scotty"
)

// PlainQ's CLI is driven by AI agents at least as often as by humans, so every
// command describes itself in one place: a commandSpec. The spec is the single
// source of truth behind three surfaces that must never drift apart — the help
// text a command prints, the machine-readable tree served by
// "plainq schema -target=cli", and the reference documentation.

// Exit codes the binary returns. They are part of the CLI contract: an agent
// branches on them instead of pattern-matching error text.
const (
	// exitOK is returned when the command did what was asked.
	exitOK = 0

	// exitFailure is returned when the command ran but failed — the server was
	// unreachable, the queue does not exist, the request was rejected.
	exitFailure = 1

	// exitUsage is returned when the invocation itself was wrong — an unknown
	// flag, a missing argument, a malformed queue id. Retrying the same command
	// will not help; the arguments have to change.
	exitUsage = 2
)

// rootName is the name the CLI calls itself in help output and examples. It is
// overridden in main with the actual binary name so that generated usage lines
// stay copy-pasteable when the binary is installed under a different name.
var rootName = "plainq"

// commandEffect classifies what running a command does to server state. Agents
// use it to decide what is safe to run while exploring.
type commandEffect string

const (
	// effectReadOnly marks a command that only reads state.
	effectReadOnly commandEffect = "read-only"

	// effectMutating marks a command that creates or changes state.
	effectMutating commandEffect = "mutating"

	// effectDestructive marks a command that removes data irrecoverably. None of
	// these prompt for confirmation.
	effectDestructive commandEffect = "destructive"
)

// argSpec documents one positional argument.
type argSpec struct {
	// Name is the placeholder shown in usage lines, without angle brackets.
	Name string `json:"name"`

	// Description explains what the argument is and where to get it.
	Description string `json:"description"`

	// Required reports whether the command fails without this argument.
	Required bool `json:"required"`

	// Variadic reports whether the argument may be repeated.
	Variadic bool `json:"variadic"`
}

// exampleSpec is a copy-pasteable invocation.
type exampleSpec struct {
	// Description says what the example accomplishes.
	Description string `json:"description"`

	// Command is the shell command to run.
	Command string `json:"command"`
}

// flagSpec is the machine-readable description of a single flag. It is derived
// from the live *flag.FlagSet so it cannot fall out of sync with the code.
type flagSpec struct {
	// Name is the flag name without a leading dash.
	Name string `json:"name"`

	// Type is a human-readable value type: string, int, uint, bool, duration.
	Type string `json:"type"`

	// Default is the value used when the flag is omitted.
	Default string `json:"default"`

	// Usage describes what the flag does.
	Usage string `json:"usage"`

	// Repeatable reports whether passing the flag several times accumulates
	// values instead of overwriting them.
	Repeatable bool `json:"repeatable"`
}

// exitCodeSpec documents one exit code.
type exitCodeSpec struct {
	// Code is the process exit status.
	Code int `json:"code"`

	// Meaning explains when the CLI returns it.
	Meaning string `json:"meaning"`
}

// exitCodeSpecs is the documented exit-code contract.
func exitCodeSpecs() []exitCodeSpec {
	return []exitCodeSpec{
		{Code: exitOK, Meaning: "success"},
		{
			Code:    exitFailure,
			Meaning: "the command ran but failed: server unreachable, queue not found, request rejected",
		},
		{
			Code:    exitUsage,
			Meaning: "usage error: unknown flag, missing or malformed argument. Retrying unchanged will not help",
		},
	}
}

// cliConventions are the rules that hold for every command. They are printed in
// the root help and included in the machine-readable schema so an agent can
// learn the whole calling convention from one command.
func cliConventions() []string {
	return []string{
		"Flags may be written before or after positional arguments: " +
			`"plainq send -message=hi <queue-id>" and "plainq send <queue-id> -message=hi" are equivalent.`,
		`Flags accept both "-flag value" and "-flag=value", with one or two leading dashes.`,
		"Every command that prints a result accepts -json, which writes the raw server response to stdout.",
		"-json output is protobuf JSON: fields at their zero value are omitted, 64-bit integers are " +
			"quoted strings, and byte fields such as a message body are base64.",
		"Errors go to stderr. stdout carries only command output, so -json output is always parseable.",
		`No command prompts for confirmation. Every command except "plainq tui" is safe to run ` +
			`unattended; tui needs a terminal and runs until quit, and is the only command with ` +
			`"interactive": true in this schema.`,
		`Queue ids are 20-character identifiers returned by "plainq create"; queue names are not accepted in their place.`,
		`Run "plainq schema -target=cli -json" for this whole surface in machine-readable form.`,
	}
}

// commandSpec declares one command: what it does, what it takes, what it
// returns, and what it costs to run.
type commandSpec struct {
	// Name is the word that invokes the command.
	Name string

	// Short is a one-line summary shown in command listings.
	Short string

	// Long is the full description shown in the command's own help.
	Long string

	// Args documents the positional arguments in the order they are read.
	Args []argSpec

	// Examples are copy-pasteable invocations.
	Examples []exampleSpec

	// Effect classifies what the command does to server state.
	Effect commandEffect

	// Blocking marks a command that runs until interrupted. An agent should not
	// run one of these in the foreground while waiting for it to return.
	Blocking bool

	// Interactive marks a command that drives a terminal and cannot be
	// scripted. Blocking is not enough to express this on its own: "serve"
	// blocks but runs happily headless, while an interactive command fails or
	// hangs the moment there is no TTY.
	Interactive bool

	// SetFlags registers the command's flags, exactly as scotty expects.
	SetFlags func(flags *scotty.FlagSet)

	// Run executes the command.
	Run func(cmd *scotty.Command, args []string) error

	// Subcommands are nested commands.
	Subcommands []*commandSpec

	// parent points at the spec this one hangs off, or nil for the root.
	parent *commandSpec

	// cmd caches the built scotty command so that repeated lookups — argument
	// normalization, schema rendering, execution — all share one FlagSet.
	cmd *scotty.Command
}

// command builds (once) and returns the scotty command for this spec.
func (s *commandSpec) command() *scotty.Command {
	if s.cmd != nil {
		return s.cmd
	}

	s.cmd = &scotty.Command{
		Name:  s.Name,
		Short: s.Short,
		Long:  s.Long,
		Run:   s.Run,

		// scotty assigns its own usage renderer before calling SetFlags, so this
		// is the hook that lets a command print help worth reading.
		SetFlags: func(flags *scotty.FlagSet) {
			if s.SetFlags != nil {
				s.SetFlags(flags)
			}

			flags.Usage = func() { s.printUsage(flags.Output()) }
		},
	}

	if len(s.Subcommands) > 0 {
		subcommands := make([]*scotty.Command, 0, len(s.Subcommands))

		for _, sub := range s.Subcommands {
			sub.parent = s
			subcommands = append(subcommands, sub.command())
		}

		s.cmd.AddSubcommands(subcommands...)
	}

	return s.cmd
}

// lookup returns the subcommand spec registered under name, or nil.
func (s *commandSpec) lookup(name string) *commandSpec {
	for _, sub := range s.Subcommands {
		if sub.Name == name {
			return sub
		}
	}

	return nil
}

// root walks up to the top of the command tree. Parents are wired when the
// tree is built, so this is only meaningful once command has been called on the
// root — which Exec guarantees before any Run function fires.
func (s *commandSpec) root() *commandSpec {
	if s.parent == nil {
		return s
	}

	return s.parent.root()
}

// path returns the full invocation prefix, e.g. "plainq cluster status".
func (s *commandSpec) path() string {
	if s.parent == nil {
		return rootName
	}

	return s.parent.path() + " " + s.Name
}

// flags returns the command's flags in machine-readable form.
func (s *commandSpec) flags() []flagSpec {
	var specs []flagSpec

	s.command().Flags().VisitAll(func(f *flag.Flag) {
		typeName, repeatable := flagValueType(f.Value)

		specs = append(specs, flagSpec{
			Name:       f.Name,
			Type:       typeName,
			Default:    f.DefValue,
			Usage:      f.Usage,
			Repeatable: repeatable,
		})
	})

	return specs
}

// usageLine renders the one-line call signature of the command.
func (s *commandSpec) usageLine() string {
	var b strings.Builder

	b.WriteString(s.path())

	if len(s.Subcommands) > 0 {
		b.WriteString(" <command>")
	}

	if len(s.flags()) > 0 {
		b.WriteString(" [flags]")
	}

	for _, arg := range s.Args {
		b.WriteString(" " + arg.placeholder())
	}

	return b.String()
}

// placeholder renders the argument as it appears in a usage line: angle
// brackets for required arguments, square brackets for optional ones, and a
// trailing ellipsis for repeatable ones.
func (a argSpec) placeholder() string {
	switch {
	case a.Required && a.Variadic:
		return "<" + a.Name + ">..."

	case a.Required:
		return "<" + a.Name + ">"

	case a.Variadic:
		return "[" + a.Name + "...]"

	default:
		return "[" + a.Name + "]"
	}
}

// printUsage writes the command's help. The layout is deliberately regular —
// fixed section headings in a fixed order — so that it reads well to a human
// and parses reliably for an agent that only has the help text to go on.
func (s *commandSpec) printUsage(w io.Writer) {
	var b strings.Builder

	if s.Short != "" {
		fmt.Fprintf(&b, "%s - %s\n\n", s.path(), strings.TrimSuffix(s.Short, "."))
	} else {
		fmt.Fprintf(&b, "%s\n\n", s.path())
	}

	if s.Long != "" {
		b.WriteString(strings.TrimSpace(s.Long) + "\n\n")
	}

	fmt.Fprintf(&b, "Usage:\n  %s\n", s.usageLine())

	s.printSubcommands(&b)
	s.printArguments(&b)
	s.printFlags(&b)
	s.printExamples(&b)
	s.printFooter(&b)

	fmt.Fprint(w, b.String())
}

// printSubcommands lists nested commands with their summaries.
func (s *commandSpec) printSubcommands(b *strings.Builder) {
	if len(s.Subcommands) == 0 {
		return
	}

	b.WriteString("\nCommands:\n")

	width := 0

	for _, sub := range s.Subcommands {
		width = max(width, len(sub.Name))
	}

	for _, sub := range s.Subcommands {
		writeDefinition(b, sub.Name, width, sub.Short)
	}
}

// printArguments documents the positional arguments.
func (s *commandSpec) printArguments(b *strings.Builder) {
	if len(s.Args) == 0 {
		return
	}

	b.WriteString("\nArguments:\n")

	width := 0

	for _, arg := range s.Args {
		width = max(width, len(arg.placeholder()))
	}

	for _, arg := range s.Args {
		writeDefinition(b, arg.placeholder(), width, arg.Description)
	}
}

// printFlags documents the flags, including their types and defaults. stdlib
// flag omits defaults that equal the zero value; we print them anyway, because
// "what happens if I leave this out" is exactly what a caller needs to know.
func (s *commandSpec) printFlags(b *strings.Builder) {
	specs := s.flags()
	if len(specs) == 0 {
		return
	}

	b.WriteString("\nFlags:\n")

	names := make([]string, 0, len(specs))
	width := 0

	for _, f := range specs {
		name := "-" + f.Name

		// Bool flags are written bare ("-json"), so showing a value placeholder
		// after them would suggest an argument they do not take.
		if f.Type != flagTypeBool {
			name += " " + f.Type
		}

		names = append(names, name)
		width = max(width, len(name))
	}

	for i, f := range specs {
		description := f.Usage

		if f.Repeatable {
			description += " (repeatable)"
		}

		// stdlib flag hides defaults that equal the zero value. We print them
		// anyway: "what happens if I leave this out" is exactly what a caller
		// needs to know, and an empty default is an answer, not an absence —
		// which is also why string defaults are quoted and numbers are not.
		if f.Type == flagTypeString || f.Type == flagTypeValue {
			description += fmt.Sprintf(" (default %q)", f.Default)
		} else {
			description += fmt.Sprintf(" (default %s)", f.Default)
		}

		writeDefinition(b, names[i], width, description)
	}
}

// printExamples renders the worked examples.
func (s *commandSpec) printExamples(b *strings.Builder) {
	if len(s.Examples) == 0 {
		return
	}

	b.WriteString("\nExamples:\n")

	for i, example := range s.Examples {
		if i > 0 {
			b.WriteString("\n")
		}

		if example.Description != "" {
			fmt.Fprintf(b, "  # %s\n", example.Description)
		}

		fmt.Fprintf(b, "  %s\n", example.Command)
	}
}

// printFooter prints the parts of the contract that apply to every command:
// what running it costs, how it exits, and where to find the rest.
func (s *commandSpec) printFooter(b *strings.Builder) {
	if s.Effect != "" {
		fmt.Fprintf(b, "\nEffect: %s\n", s.Effect)
	}

	if s.Interactive {
		b.WriteString("\nThis command needs an interactive terminal and runs until you quit it.\n" +
			"It is the one command here that cannot be scripted.\n")
	} else if s.Blocking {
		b.WriteString("\nThis command runs until interrupted. Start it in the background\n" +
			"if you need the shell back.\n")
	}

	if s.parent == nil {
		b.WriteString("\nConventions:\n")

		for _, convention := range cliConventions() {
			fmt.Fprintf(b, "  - %s\n", wrapText(convention, helpWidth-4, "    "))
		}
	}

	b.WriteString("\nExit codes:\n")

	for _, code := range exitCodeSpecs() {
		writeDefinition(b, strconv.Itoa(code.Code), 1, code.Meaning)
	}

	if len(s.Subcommands) > 0 {
		fmt.Fprintf(b, "\nRun %q for details on a command.\n", s.path()+" <command> -h")
	}
}

// helpWidth is the column help output wraps at. Terminals are wider than this,
// but a paragraph that runs the full width of a modern terminal is unpleasant
// to read and awkward to quote.
const helpWidth = 96

// writeDefinition writes one "  term  description" row, wrapping the
// description into a hanging indent under the description column.
func writeDefinition(b *strings.Builder, term string, termWidth int, description string) {
	indent := strings.Repeat(" ", termWidth+4)

	fmt.Fprintf(b, "  %-*s  %s\n", termWidth, term, wrapText(description, helpWidth-len(indent), indent))
}

// wrapText breaks text on word boundaries so that no line exceeds width, and
// indents every line after the first. A word longer than width is left alone
// rather than broken, because the long words here are flag names, paths and
// example commands, none of which survive being split.
func wrapText(text string, width int, indent string) string {
	if width < 1 {
		return text
	}

	var (
		b    strings.Builder
		line int
	)

	for i, word := range strings.Fields(text) {
		switch {
		case i == 0:
			b.WriteString(word)

			line = len(word)

		case line+1+len(word) <= width:
			b.WriteString(" " + word)

			line += 1 + len(word)

		default:
			b.WriteString("\n" + indent + word)

			line = len(word)
		}
	}

	return b.String()
}

// Type names shown for flag values. They name what a caller writes on the
// command line, not the Go type behind it.
const (
	flagTypeString   = "string"
	flagTypeBool     = "bool"
	flagTypeInt      = "int"
	flagTypeUint     = "uint"
	flagTypeFloat    = "float"
	flagTypeDuration = "duration"
	flagTypeValue    = "value"
)

// flagType is how one flag value is presented: its type name, and whether
// repeating the flag accumulates values instead of overwriting them.
type flagType struct {
	name       string
	repeatable bool
}

// flagTypesByKind maps the kind behind a flag value to how it is presented.
// Kinds with no entry fall back to flagTypeValue.
var flagTypesByKind = map[reflect.Kind]flagType{
	reflect.String:  {name: flagTypeString},
	reflect.Bool:    {name: flagTypeBool},
	reflect.Int:     {name: flagTypeInt},
	reflect.Int8:    {name: flagTypeInt},
	reflect.Int16:   {name: flagTypeInt},
	reflect.Int32:   {name: flagTypeInt},
	reflect.Int64:   {name: flagTypeInt},
	reflect.Uint:    {name: flagTypeUint},
	reflect.Uint8:   {name: flagTypeUint},
	reflect.Uint16:  {name: flagTypeUint},
	reflect.Uint32:  {name: flagTypeUint},
	reflect.Uint64:  {name: flagTypeUint},
	reflect.Float32: {name: flagTypeFloat},
	reflect.Float64: {name: flagTypeFloat},
	reflect.Slice:   {name: flagTypeString, repeatable: true},
	reflect.Array:   {name: flagTypeString, repeatable: true},
}

// flagValueType maps a flag's value to a readable type name, and reports
// whether repeating the flag accumulates values.
func flagValueType(value flag.Value) (string, bool) {
	if boolFlag, ok := value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
		return flagTypeBool, false
	}

	valueType := reflect.TypeOf(value)
	if valueType == nil {
		return flagTypeValue, false
	}

	// time.Duration is an int64 underneath, so the kind alone cannot tell the
	// two apart; the concrete flag type can.
	if strings.HasSuffix(valueType.String(), "durationValue") {
		return flagTypeDuration, false
	}

	if valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}

	found, ok := flagTypesByKind[valueType.Kind()]
	if !ok {
		return flagTypeValue, false
	}

	return found.name, found.repeatable
}

// usageError marks an error caused by how the command was invoked rather than
// by what happened when it ran. It selects the exitUsage status so that a
// caller can tell "you asked wrong" from "it went wrong".
type usageError struct{ err error }

// Error implements the error interface.
func (e *usageError) Error() string { return e.err.Error() }

// Unwrap exposes the wrapped error to errors.Is and errors.As.
func (e *usageError) Unwrap() error { return e.err }

// usagef builds a usageError from a format string.
func usagef(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

// reportError writes err to w and returns the exit code the binary should use.
// Errors never go to stdout: an agent that captured stdout to parse -json
// output must not find a diagnostic mixed into it.
func reportError(w io.Writer, err error) int {
	// scotty wraps whatever Run returns; the prefix adds nothing for a reader
	// who already knows which command they ran.
	message := strings.TrimPrefix(err.Error(), "command failed: ")

	fmt.Fprintf(w, "%s: %s\n", rootName, message)

	var usage *usageError
	if errors.As(err, &usage) || strings.HasPrefix(message, "unknown command:") {
		return exitUsage
	}

	return exitFailure
}
