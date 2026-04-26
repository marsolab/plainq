package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/heartwilltell/scotty"
)

type plainqContextConfig struct {
	Current  plainqContext   `json:"current"`
	Contexts []plainqContext `json:"contexts"`
}

type plainqContext struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func contextCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "ctx",
		Short: "Manages plainq client contexts",
	}

	cmd.AddSubcommands(
		contextInitCommand(),
		contextListCommand(),
	)

	return &cmd
}

func contextInitCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "init",
		Short: "Create context configuration file",
		Run: func(_ *scotty.Command, _ []string) error {
			//nolint:godox // tracking item: default-location context creation under ~/.config/plainq/context.json.
			// TODO: create context in default location at ~/.config/plainq/context.json.
			f, createErr := createContextFile()
			if createErr != nil {
				if errors.Is(createErr, os.ErrExist) {
					fmt.Println("Context file already exists")
					return nil
				}

				return createErr
			}

			ctxConfig := plainqContextConfig{
				Current: plainqContext{
					Name: "default", Endpoint: "localhost:8080",
				},
				Contexts: []plainqContext{
					{Name: "default", Endpoint: "localhost:8080"},
				},
			}

			if err := json.NewEncoder(f).Encode(&ctxConfig); err != nil {
				return fmt.Errorf("encode context file content: %w", err)
			}

			fmt.Println("Context file created")
			return nil
		},
	}

	return &cmd
}

func contextListCommand() *scotty.Command {
	cmd := scotty.Command{
		Name:  "list",
		Short: "show list of available contexts",
		Run: func(_ *scotty.Command, _ []string) error {
			f, readErr := readContextFile()
			if readErr != nil {
				if errors.Is(readErr, os.ErrNotExist) {
					return fmt.Errorf("context file doesn't exist: execute %q", "plainq ctx init")
				}
			}
			defer f.Close()

			var ctxConfig plainqContextConfig

			if err := json.NewDecoder(f).Decode(&ctxConfig); err != nil {
				return fmt.Errorf("decode contex file: %w", err)
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

	return &cmd
}

func readContextFile() (io.ReadCloser, error) {
	var (
		f   io.ReadCloser
		err error
	)

	switch runtime.GOOS {
	case "darwin":
		f, err = os.Open("~/.config/plainq/context.json")

	default:
		return nil, errors.New("unsupported operating system")
	}

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		return nil, fmt.Errorf("open context file: %w", err)
	}

	return f, nil
}

func createContextFile() (*os.File, error) {
	var (
		f   *os.File
		err error
	)

	switch runtime.GOOS {
	case "darwin":
		f, err = os.Create("~/.config/plainq/context.json")

	default:
		return nil, errors.New("unsupported operating system")
	}

	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, err
		}

		return nil, fmt.Errorf("create context file: %w", err)
	}

	return f, nil
}
