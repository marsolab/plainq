// Package tui implements PlainQ's interactive terminal UI built with
// Bubble Tea. It offers a queue browser plus send, receive, purge, and delete
// actions against a running PlainQ server.
package tui

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// viewState enumerates the screens of the TUI.
type viewState int

const (
	stateList viewState = iota
	stateDetail
	stateSend
)

const (
	// inputCharLimit caps the length of a message body typed in the TUI.
	inputCharLimit = 4096

	// tableHeightPadding reserves rows for the header and footer chrome.
	tableHeightPadding = 8
)

// model is the root Bubble Tea model.
type model struct {
	client Client
	addr   string
	keys   keyMap

	state    viewState
	table    table.Model
	input    textinput.Model
	queues   []*v1.DescribeQueueResponse
	selected *v1.DescribeQueueResponse
	messages []*v1.ReceiveMessage

	status  string
	errText string
	loading bool

	width  int
	height int
}

// newModel builds the initial model wired to the given client and address.
func newModel(addr string, client Client) model {
	columns := []table.Column{
		{Title: "ID", Width: 22},
		{Title: "Name", Width: 24},
		{Title: "Visibility", Width: 11},
		{Title: "Max recv", Width: 9},
		{Title: "Policy", Width: 12},
	}

	queueTable := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
	)

	input := textinput.New()
	input.Placeholder = "message body"
	input.CharLimit = inputCharLimit

	return model{
		client: client,
		addr:   addr,
		keys:   defaultKeys(),
		state:  stateList,
		table:  queueTable,
		input:  input,
		status: "loading queues…",
	}
}

// Init implements tea.Model.
func (m model) Init() tea.Cmd {
	return listQueuesCmd(m.client)
}

// onQueuesLoaded refreshes the table rows from a loaded queue list.
func (m model) onQueuesLoaded(queues []*v1.DescribeQueueResponse) model {
	m.queues = queues
	m.loading = false
	m.errText = ""
	m.status = fmt.Sprintf("%d queue(s)", len(queues))

	rows := make([]table.Row, 0, len(queues))
	for _, queue := range queues {
		rows = append(rows, table.Row{
			queue.GetQueueId(),
			queue.GetQueueName(),
			fmt.Sprintf("%ds", queue.GetVisibilityTimeoutSeconds()),
			strconv.FormatUint(uint64(queue.GetMaxReceiveAttempts()), 10),
			evictionPolicyName(queue.GetEvictionPolicy()),
		})
	}

	m.table.SetRows(rows)

	return m
}

// currentQueue returns the queue under the table cursor, or nil.
func (m model) currentQueue() *v1.DescribeQueueResponse {
	cursor := m.table.Cursor()
	if cursor < 0 || cursor >= len(m.queues) {
		return nil
	}

	return m.queues[cursor]
}

// evictionPolicyName maps an eviction policy to a short label.
func evictionPolicyName(policy v1.EvictionPolicy) string {
	switch policy {
	case v1.EvictionPolicy_EVICTION_POLICY_DROP:
		return "drop"
	case v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER:
		return "dead-letter"
	case v1.EvictionPolicy_EVICTION_POLICY_REORDER:
		return "reorder"
	case v1.EvictionPolicy_EVICTION_POLICY_UNSPECIFIED:
		return "unspecified"
	default:
		return "unspecified"
	}
}
