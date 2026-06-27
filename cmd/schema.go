package main

import (
	"fmt"
	"os"

	"github.com/heartwilltell/scotty"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
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

// schemaCommand prints the gRPC API surface so that AI agents and code
// generators can discover the available operations without external tooling.
func schemaCommand() *scotty.Command {
	var jsonOut bool

	cmd := scotty.Command{
		Name:  "schema",
		Short: "Print the gRPC API surface (useful for AI agents and codegen)",
		SetFlags: func(flags *scotty.FlagSet) {
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			services := collectSchema()

			if jsonOut {
				return encodeJSON(os.Stdout, services)
			}

			for _, service := range services {
				fmt.Printf("service %s\n", service.Service)

				for _, method := range service.Methods {
					fmt.Printf("  rpc %s(%s) returns (%s)\n", method.Name, method.Input, method.Output)
				}
			}

			return nil
		},
	}

	return &cmd
}

// collectSchema reads the embedded protobuf file descriptor and returns the
// services and methods it declares.
func collectSchema() []schemaService {
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
