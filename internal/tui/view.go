package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// Styles shared across the views.
var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Padding(0, 1)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	errStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	labelStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("69"))
	boxStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

const (
	listHelp   = "↑/↓ move • enter open • r refresh • d delete • q quit"
	detailHelp = "s send • g receive • p purge • esc back • q quit"
	sendHelp   = "enter send • esc cancel"
)

// View implements tea.Model.
func (m model) View() string {
	switch m.state {
	case stateDetail:
		return m.detailView()
	case stateSend:
		return m.sendView()
	case stateList:
		return m.listView()
	default:
		return m.listView()
	}
}

// header renders the top bar with the product name and server address.
func (m model) header() string {
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		titleStyle.Render("PlainQ TUI"),
		" ",
		statusStyle.Render(m.addr),
	)
}

// footer renders the status/error line and the contextual help.
func (m model) footer(help string) string {
	var builder strings.Builder

	switch {
	case m.errText != "":
		builder.WriteString(errStyle.Render("error: " + m.errText))
		builder.WriteString("\n")
	case m.status != "":
		builder.WriteString(statusStyle.Render(m.status))
		builder.WriteString("\n")
	}

	builder.WriteString(helpStyle.Render(help))

	return builder.String()
}

// listView renders the queue table.
func (m model) listView() string {
	var builder strings.Builder

	builder.WriteString(m.header())
	builder.WriteString("\n")
	builder.WriteString(m.table.View())
	builder.WriteString("\n")
	builder.WriteString(m.footer(listHelp))

	return builder.String()
}

// detailView renders the selected queue's properties and received messages.
func (m model) detailView() string {
	var builder strings.Builder

	builder.WriteString(m.header())
	builder.WriteString("\n\n")

	if m.selected != nil {
		builder.WriteString(renderQueueDetail(m.selected))
	}

	builder.WriteString("\n")
	builder.WriteString(m.renderMessages())
	builder.WriteString("\n")
	builder.WriteString(m.footer(detailHelp))

	return builder.String()
}

// sendView renders the message composer.
func (m model) sendView() string {
	var builder strings.Builder

	name := ""
	if m.selected != nil {
		name = m.selected.GetQueueName()
	}

	builder.WriteString(m.header())
	builder.WriteString("\n\n")
	builder.WriteString(labelStyle.Render("Send message to " + name))
	builder.WriteString("\n\n")
	builder.WriteString(m.input.View())
	builder.WriteString("\n\n")
	builder.WriteString(m.footer(sendHelp))

	return builder.String()
}

// renderQueueDetail renders a queue's properties inside a rounded box.
func renderQueueDetail(queue *v1.DescribeQueueResponse) string {
	lines := []string{
		labelStyle.Render("Name:    ") + queue.GetQueueName(),
		labelStyle.Render("ID:      ") + queue.GetQueueId(),
		labelStyle.Render("Visible: ") + fmt.Sprintf("%ds", queue.GetVisibilityTimeoutSeconds()),
		labelStyle.Render("MaxRecv: ") + strconv.FormatUint(uint64(queue.GetMaxReceiveAttempts()), 10),
		labelStyle.Render("Policy:  ") + evictionPolicyName(queue.GetEvictionPolicy()),
	}

	return boxStyle.Render(strings.Join(lines, "\n"))
}

// renderMessages renders the most recently received messages.
func (m model) renderMessages() string {
	if len(m.messages) == 0 {
		return statusStyle.Render("no messages received yet — press g to receive")
	}

	rows := make([]string, 0, len(m.messages))
	for _, msg := range m.messages {
		rows = append(rows, msg.GetId()+"  "+string(msg.GetBody()))
	}

	header := labelStyle.Render("Received messages (" + strconv.Itoa(len(m.messages)) + "):")

	return header + "\n" + boxStyle.Render(strings.Join(rows, "\n"))
}
