package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/heartwilltell/scotty"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// Schema targets. A caller asks for the surface they are about to program
// against: the command line, the gRPC API, or both.
const (
	// schemaTargetAll emits every surface. It is the default because an agent
	// that has just discovered the binary wants the whole picture.
	schemaTargetAll = "all"

	// schemaTargetCLI emits the command-line surface.
	schemaTargetCLI = "cli"

	// schemaTargetGRPC emits the gRPC surface.
	schemaTargetGRPC = "grpc"
)

// schemaMethod is a single gRPC method in machine-readable form.
type schemaMethod struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

// schemaService groups the methods of a gRPC service.
type schemaService struct {
	Service string         `json:"service"`
	Methods []schemaMethod `json:"methods"`
}

// cliCommand is one command in machine-readable form.
type cliCommand struct {
	// Path is the full invocation prefix, e.g. "plainq cluster status".
	Path string `json:"path"`

	// Name is the word that selects this command within its parent.
	Name string `json:"name"`

	// Short is a one-line summary.
	Short string `json:"short"`

	// Long is the full description.
	Long string `json:"long,omitempty"`

	// Usage is the one-line call signature.
	Usage string `json:"usage"`

	// Effect says what running the command does to server state.
	Effect commandEffect `json:"effect,omitempty"`

	// Blocking reports whether the command runs until interrupted.
	Blocking bool `json:"blocking"`

	// Interactive reports whether the command needs a terminal and therefore
	// cannot be run unattended.
	Interactive bool `json:"interactive"`

	// Arguments are the positional arguments, in order.
	Arguments []argSpec `json:"arguments,omitempty"`

	// Flags are the flags the command accepts.
	Flags []flagSpec `json:"flags,omitempty"`

	// Examples are copy-pasteable invocations.
	Examples []exampleSpec `json:"examples,omitempty"`

	// Subcommands are the nested commands.
	Subcommands []cliCommand `json:"subcommands,omitempty"`
}

// cliSchema is the machine-readable description of the whole command line.
type cliSchema struct {
	// Binary is the name the CLI is invoked by.
	Binary string `json:"binary"`

	// Description explains what the tool is for.
	Description string `json:"description"`

	// Conventions are the rules that hold for every command.
	Conventions []string `json:"conventions"`

	// ExitCodes documents what each exit status means.
	ExitCodes []exitCodeSpec `json:"exitCodes"`

	// Commands is the command tree.
	Commands []cliCommand `json:"commands"`
}

// schema is what the schema command emits: whichever surfaces were asked for.
type schema struct {
	CLI  *cliSchema      `json:"cli,omitempty"`
	GRPC []schemaService `json:"grpc,omitempty"`
}

// schemaCommand prints PlainQ's surfaces in machine-readable form so that AI
// agents and code generators can discover every operation without scraping help
// text or reading the source.
func schemaCommand() *commandSpec {
	var (
		jsonOut bool
		target  string
	)

	spec := &commandSpec{
		Name:   "schema",
		Short:  "Print the CLI and gRPC surfaces (for AI agents and codegen)",
		Effect: effectReadOnly,
		Long: "Describes PlainQ to a program. The CLI surface lists every command with its\n" +
			"arguments, flags, defaults, effects, and worked examples; the gRPC surface\n" +
			"lists every service method with its request and response types.\n\n" +
			"This command talks to no server and needs no configuration, so it is always\n" +
			"safe to run first when working out how to drive PlainQ.",
		Examples: []exampleSpec{
			{
				Description: "Discover the whole tool, machine-readably.",
				Command:     "plainq schema -json",
			},
			{
				Description: "List every command with its call signature.",
				Command:     "plainq schema -target=cli",
			},
			{
				Description: "Find which commands change state.",
				Command: "plainq schema -target=cli -json |" +
					` jq -r '.cli.commands[] | recurse(.subcommands[]?) | select(.effect != "read-only") | .path'`,
			},
			{
				Description: "List the gRPC methods for codegen.",
				Command:     "plainq schema -target=grpc -json",
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)

			flags.StringVar(&target, "target", schemaTargetAll,
				`which surface to describe: "all", "cli" or "grpc"`,
			)
		},
	}

	spec.Run = func(_ *scotty.Command, _ []string) error {
		out, buildErr := buildSchema(spec.root(), target)
		if buildErr != nil {
			return buildErr
		}

		if jsonOut {
			return encodeJSON(os.Stdout, out)
		}

		printSchemaText(os.Stdout, out)

		return nil
	}

	return spec
}

// buildSchema assembles the requested surfaces.
func buildSchema(root *commandSpec, target string) (schema, error) {
	var out schema

	switch strings.ToLower(target) {
	case schemaTargetAll:
		out.CLI = collectCLISchema(root)
		out.GRPC = collectGRPCSchema()

	case schemaTargetCLI:
		out.CLI = collectCLISchema(root)

	case schemaTargetGRPC:
		out.GRPC = collectGRPCSchema()

	default:
		return out, usagef(`unknown schema target: %q, should be one of: ["all", "cli", "grpc"]`, target)
	}

	return out, nil
}

// collectCLISchema walks the command tree and renders it machine-readably.
func collectCLISchema(root *commandSpec) *cliSchema {
	if root == nil {
		return nil
	}

	commands := make([]cliCommand, 0, len(root.Subcommands))
	for _, sub := range root.Subcommands {
		commands = append(commands, collectCLICommand(sub))
	}

	return &cliSchema{
		Binary:      rootName,
		Description: strings.TrimSpace(root.Long),
		Conventions: cliConventions(),
		ExitCodes:   exitCodeSpecs(),
		Commands:    commands,
	}
}

// collectCLICommand renders one command and everything under it.
func collectCLICommand(spec *commandSpec) cliCommand {
	command := cliCommand{
		Path:        spec.path(),
		Name:        spec.Name,
		Short:       spec.Short,
		Long:        strings.TrimSpace(spec.Long),
		Usage:       spec.usageLine(),
		Effect:      spec.Effect,
		Blocking:    spec.Blocking,
		Interactive: spec.Interactive,

		Arguments: spec.Args,
		Flags:     spec.flags(),
		Examples:  spec.Examples,
	}

	for _, sub := range spec.Subcommands {
		command.Subcommands = append(command.Subcommands, collectCLICommand(sub))
	}

	return command
}

// collectGRPCSchema reads the embedded protobuf file descriptor and returns the
// services and methods it declares.
func collectGRPCSchema() []schemaService {
	services := v1.File_v1_schema_proto.Services()
	result := make([]schemaService, 0, services.Len())

	for i := range services.Len() {
		service := services.Get(i)
		methods := service.Methods()
		methodList := make([]schemaMethod, 0, methods.Len())

		for j := range methods.Len() {
			method := methods.Get(j)
			methodList = append(methodList, schemaMethod{
				Name:   string(method.Name()),
				Input:  string(method.Input().Name()),
				Output: string(method.Output().Name()),
			})
		}

		result = append(result, schemaService{
			Service: string(service.FullName()),
			Methods: methodList,
		})
	}

	return result
}

// printSchemaText renders the schema for a human reader.
func printSchemaText(w io.Writer, out schema) {
	if out.CLI != nil {
		printCLISchemaText(w, out.CLI)
	}

	if out.GRPC != nil {
		if out.CLI != nil {
			fmt.Fprintln(w)
		}

		for _, service := range out.GRPC {
			fmt.Fprintf(w, "service %s\n", service.Service)

			for _, method := range service.Methods {
				fmt.Fprintf(w, "  rpc %s(%s) returns (%s)\n", method.Name, method.Input, method.Output)
			}
		}
	}
}

// printCLISchemaText renders the command surface as a cheat sheet: one call
// signature per command, with the state-changing ones marked.
func printCLISchemaText(w io.Writer, cli *cliSchema) {
	fmt.Fprintf(w, "%s commands\n\n", cli.Binary)

	for _, command := range cli.Commands {
		printCLICommandText(w, command)
	}

	fmt.Fprintln(w, "Conventions:")

	for _, convention := range cli.Conventions {
		fmt.Fprintf(w, "  - %s\n", convention)
	}

	fmt.Fprintln(w, "\nExit codes:")

	for _, code := range cli.ExitCodes {
		fmt.Fprintf(w, "  %d  %s\n", code.Code, code.Meaning)
	}
}

// printCLICommandText renders one command and its subcommands.
func printCLICommandText(w io.Writer, command cliCommand) {
	if len(command.Subcommands) > 0 {
		for _, sub := range command.Subcommands {
			printCLICommandText(w, sub)
		}

		return
	}

	fmt.Fprintf(w, "  %s\n", command.Usage)
	fmt.Fprintf(w, "      %s [%s]\n\n", command.Short, command.Effect)
}
