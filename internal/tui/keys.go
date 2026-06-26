package tui

import "github.com/charmbracelet/bubbles/key"

// keyMap holds every key binding used across the TUI views.
type keyMap struct {
	Up      key.Binding
	Down    key.Binding
	Enter   key.Binding
	Back    key.Binding
	Refresh key.Binding
	Send    key.Binding
	Receive key.Binding
	Purge   key.Binding
	Delete  key.Binding
	Quit    key.Binding
}

// defaultKeys returns the default key bindings.
func defaultKeys() keyMap {
	return keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "open"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "refresh"),
		),
		Send: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "send"),
		),
		Receive: key.NewBinding(
			key.WithKeys("g"),
			key.WithHelp("g", "receive"),
		),
		Purge: key.NewBinding(
			key.WithKeys("p"),
			key.WithHelp("p", "purge"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}
