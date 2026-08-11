package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/heartwilltell/scotty"
)

const (
	// envContextFile overrides where the context file lives. It exists so that
	// a caller with no writable home directory — a container, a CI job, an agent
	// sandbox — can still keep a context.
	envContextFile = "PLAINQ_CONTEXT_FILE"

	// envGRPCAddr overrides the gRPC address without passing a flag on every
	// call.
	envGRPCAddr = "PLAINQ_ADDR"

	// contextDirPerm is the permission for the context directory.
	contextDirPerm = 0o755

	// contextFilePerm is the permission for the context file.
	contextFilePerm = 0o600
)

type plainqContextConfig struct {
	Current  plainqContext   `json:"current"`
	Contexts []plainqContext `json:"contexts"`
}

type plainqContext struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func contextCommand() *commandSpec {
	return &commandSpec{
		Name:   "ctx",
		Short:  "Manage saved server endpoints",
		Effect: effectReadOnly,
		Long: "A context is a named gRPC endpoint. The current context supplies the\n" +
			"default for -grpc.addr, so a command can be run without repeating the\n" +
			"address every time.\n\n" +
			"The address is resolved in this order, first match wins:\n" +
			"  1. the -grpc.addr flag\n" +
			"  2. the " + envGRPCAddr + " environment variable\n" +
			"  3. the current context's endpoint\n" +
			"  4. " + defaultGRPCAddr + "\n\n" +
			"The file lives at " + defaultContextPathForHelp() + "\n" +
			"(override with " + envContextFile + "). Adding or switching contexts means\n" +
			"editing that file; it is plain JSON.",
		Subcommands: []*commandSpec{
			contextInitCommand(),
			contextListCommand(),
		},
	}
}

func contextInitCommand() *commandSpec {
	return &commandSpec{
		Name:   "init",
		Short:  "Create the context file",
		Effect: effectMutating,
		Long: "Writes a context file containing a single \"default\" context pointing at\n" +
			defaultGRPCAddr + ". Does nothing if the file already exists.",
		Examples: []exampleSpec{
			{Description: "Create the context file.", Command: "plainq ctx init"},
		},
		Run: func(_ *scotty.Command, _ []string) error {
			path, pathErr := contextFilePath()
			if pathErr != nil {
				return pathErr
			}

			if err := os.MkdirAll(filepath.Dir(path), contextDirPerm); err != nil {
				return fmt.Errorf("create context directory: %w", err)
			}

			// O_EXCL is what makes "already exists" detectable; os.Create would
			// silently truncate a context the caller had configured.
			f, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, contextFilePerm)
			if createErr != nil {
				if errors.Is(createErr, os.ErrExist) {
					fmt.Printf("context file already exists\t%s\n", path)

					return nil
				}

				return fmt.Errorf("create context file: %w", createErr)
			}

			ctxConfig := plainqContextConfig{
				Current: plainqContext{
					Name: "default", Endpoint: defaultGRPCAddr,
				},
				Contexts: []plainqContext{
					{Name: "default", Endpoint: defaultGRPCAddr},
				},
			}

			if err := writeContextFile(f, ctxConfig); err != nil {
				// O_EXCL means a half-written file would make every later
				// "ctx init" report that the context already exists, leaving
				// the caller stuck with the wreckage of this one. Clear it.
				if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					return errors.Join(err, fmt.Errorf("remove partial context file %s: %w", path, removeErr))
				}

				return err
			}

			fmt.Printf("created\t%s\n", path)

			return nil
		},
	}
}

// writeContextFile encodes cfg into f and closes it.
//
// The close error is reported rather than deferred away: f is open for writing,
// and Close is where a delayed write failure — a full disk, an exceeded quota,
// a network filesystem giving up — actually surfaces. Discarding it would let
// the command print "created" over a file that never landed.
func writeContextFile(f *os.File, cfg plainqContextConfig) (err error) {
	defer func() {
		closeErr := f.Close()
		if closeErr != nil && err == nil {
			err = fmt.Errorf("close context file: %w", closeErr)
		}
	}()

	if encodeErr := json.NewEncoder(f).Encode(&cfg); encodeErr != nil {
		return fmt.Errorf("encode context file content: %w", encodeErr)
	}

	return nil
}

func contextListCommand() *commandSpec {
	var jsonOut bool

	return &commandSpec{
		Name:   "list",
		Short:  "Show the current and available contexts",
		Effect: effectReadOnly,
		Long: "Prints the current context and every context in the file. Fails when no\n" +
			`context file exists yet; run "plainq ctx init" to create one.`,
		Examples: []exampleSpec{
			{Description: "Show the configured contexts.", Command: "plainq ctx list"},
			{
				Description: "Read the current endpoint programmatically.",
				Command:     "plainq ctx list -json | jq -r '.current.endpoint'",
			},
		},
		SetFlags: func(flags *scotty.FlagSet) {
			flags.BoolVar(&jsonOut, flagJSON, false,
				flagJSONUsage,
			)
		},
		Run: func(_ *scotty.Command, _ []string) error {
			path, pathErr := contextFilePath()
			if pathErr != nil {
				return pathErr
			}

			ctxConfig, readErr := readContextConfig(path)
			if readErr != nil {
				if errors.Is(readErr, os.ErrNotExist) {
					return fmt.Errorf(`no context file at %s: run "plainq ctx init" to create one`, path)
				}

				return readErr
			}

			if jsonOut {
				return encodeJSON(os.Stdout, ctxConfig)
			}

			fmt.Printf("Current context: %q endpoint: %q\n",
				ctxConfig.Current.Name,
				ctxConfig.Current.Endpoint,
			)

			fmt.Println("Contexts list:")

			for _, ctx := range ctxConfig.Contexts {
				fmt.Printf("Name: %q endpoint: %q\n",
					ctx.Name, ctx.Endpoint,
				)
			}

			return nil
		},
	}
}

// contextFilePath returns the path of the context file, honoring the
// envContextFile override.
func contextFilePath() (string, error) {
	if override := os.Getenv(envContextFile); override != "" {
		return override, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory (set %s to choose a path): %w", envContextFile, err)
	}

	return filepath.Join(home, ".config", "plainq", "context.json"), nil
}

// defaultContextPathForHelp renders the context path for help text, falling
// back to the literal form when the home directory cannot be determined. Help
// must never fail to render.
func defaultContextPathForHelp() string {
	path, err := contextFilePath()
	if err != nil {
		return filepath.Join("~", ".config", "plainq", "context.json")
	}

	return path
}

// readContextConfig loads and decodes the context file at path.
func readContextConfig(path string) (plainqContextConfig, error) {
	var ctxConfig plainqContextConfig

	f, openErr := os.Open(path)
	if openErr != nil {
		return ctxConfig, fmt.Errorf("open context file: %w", openErr)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&ctxConfig); err != nil {
		return ctxConfig, fmt.Errorf("decode context file %s: %w", path, err)
	}

	return ctxConfig, nil
}

// resolveGRPCAddr computes the default value of -grpc.addr: the environment
// wins over the saved context, which wins over the built-in default. An
// explicitly passed flag overrides all of them, because the flag package
// applies it after the default.
//
// Resolution failures are silently ignored: a missing or malformed context file
// must not stop a command that carries an explicit address on its command line.
func resolveGRPCAddr() string {
	if addr := os.Getenv(envGRPCAddr); addr != "" {
		return addr
	}

	path, pathErr := contextFilePath()
	if pathErr != nil {
		return defaultGRPCAddr
	}

	ctxConfig, readErr := readContextConfig(path)
	if readErr != nil || ctxConfig.Current.Endpoint == "" {
		return defaultGRPCAddr
	}

	return ctxConfig.Current.Endpoint
}
