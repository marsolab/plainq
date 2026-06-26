package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// minTableHeight is the smallest queue table height we render.
const minTableHeight = 3

// Run starts the TUI against the PlainQ server using the given client.
func Run(addr string, client Client) error {
	program := tea.NewProgram(newModel(addr, client), tea.WithAltScreen())

	if _, err := program.Run(); err != nil {
		return fmt.Errorf("run tui: %w", err)
	}

	return nil
}

// Update implements tea.Model.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.onResize(msg), nil
	case queuesLoadedMsg:
		return m.onQueuesLoaded(msg.queues), nil
	case messagesReceivedMsg:
		m.messages = msg.messages
		m.status = fmt.Sprintf("received %d message(s)", len(msg.messages))

		return m, nil
	case sentMsg:
		m.status = fmt.Sprintf("sent %d message(s)", len(msg.ids))

		return m, nil
	case purgedMsg:
		m.status = fmt.Sprintf("purged %d message(s)", msg.count)

		return m, nil
	case deletedMsg:
		m.status = "queue " + msg.id + " deleted"

		return m, listQueuesCmd(m.client)
	case errMsg:
		m.errText = msg.err.Error()
		m.loading = false

		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	default:
		return m, nil
	}
}

// onResize recomputes layout dimensions.
func (m model) onResize(msg tea.WindowSizeMsg) model {
	m.width = msg.Width
	m.height = msg.Height
	m.table.SetWidth(msg.Width)

	height := msg.Height - tableHeightPadding
	if height < minTableHeight {
		height = minTableHeight
	}

	m.table.SetHeight(height)

	return m
}

// handleKey routes key presses to the active view.
func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.state {
	case stateList:
		return m.handleListKey(msg)
	case stateDetail:
		return m.handleDetailKey(msg)
	case stateSend:
		return m.handleSendKey(msg)
	default:
		return m, nil
	}
}

// handleListKey handles input on the queue list view.
func (m model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Refresh):
		m.loading = true
		m.status = "refreshing…"

		return m, listQueuesCmd(m.client)
	case key.Matches(msg, m.keys.Enter):
		return m.openDetail(), nil
	case key.Matches(msg, m.keys.Delete):
		queue := m.currentQueue()
		if queue == nil {
			return m, nil
		}

		m.status = "deleting…"

		return m, deleteQueueCmd(m.client, queue.GetQueueId())
	}

	var cmd tea.Cmd

	m.table, cmd = m.table.Update(msg)

	return m, cmd
}

// openDetail switches to the detail view for the selected queue.
func (m model) openDetail() model {
	queue := m.currentQueue()
	if queue == nil {
		return m
	}

	m.selected = queue
	m.messages = nil
	m.state = stateDetail
	m.status = "viewing " + queue.GetQueueName()

	return m
}

// handleDetailKey handles input on the queue detail view.
func (m model) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.selected == nil {
		m.state = stateList

		return m, nil
	}

	id := m.selected.GetQueueId()

	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Back):
		m.state = stateList

		return m, nil
	case key.Matches(msg, m.keys.Receive):
		m.status = "receiving…"

		return m, receiveCmd(m.client, id)
	case key.Matches(msg, m.keys.Purge):
		m.status = "purging…"

		return m, purgeCmd(m.client, id)
	case key.Matches(msg, m.keys.Send):
		m.state = stateSend
		m.input.Reset()

		return m, m.input.Focus()
	default:
		return m, nil
	}
}

// handleSendKey handles input on the send-message view.
func (m model) handleSendKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back):
		m.state = stateDetail
		m.input.Blur()

		return m, nil
	case msg.Type == tea.KeyEnter:
		return m.submitSend()
	case msg.Type == tea.KeyCtrlC:
		return m, tea.Quit
	}

	var cmd tea.Cmd

	m.input, cmd = m.input.Update(msg)

	return m, cmd
}

// submitSend dispatches the typed message body to the selected queue.
func (m model) submitSend() (tea.Model, tea.Cmd) {
	body := m.input.Value()
	if body == "" || m.selected == nil {
		m.state = stateDetail

		return m, nil
	}

	id := m.selected.GetQueueId()
	m.input.Reset()
	m.input.Blur()
	m.state = stateDetail
	m.status = "sending…"

	return m, sendCmd(m.client, id, body)
}
