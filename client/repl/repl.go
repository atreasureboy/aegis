// Package repl 提供 gRPC REPL 交互终端。
package repl

import (
	"fmt"
	"strings"

	"github.com/aegis-c2/aegis/proto/aegispb"
	"github.com/peterh/liner"
)

// REPL 是交互式 REPL 终端。
type REPL struct {
	client    aegispb.OperatorServiceClient
	events    *EventStream
	name      string
	completer *completer
	line      *liner.State
	prompt    string
}

// New 创建 REPL 实例。
func New(client aegispb.OperatorServiceClient, eventCh <-chan *aegispb.EventInfo, operatorName string) *REPL {
	r := &REPL{
		client:    client,
		name:      operatorName,
		completer: newCompleter(),
		line:      liner.NewLiner(),
		prompt:    fmt.Sprintf("aegis [%s] > ", operatorName),
	}

	// Configure tab completion
	r.line.SetCompleter(r.tabCompleter)

	// Configure history
	r.line.AppendHistory("help")
	r.line.SetCtrlCAborts(true)

	// Bridge incoming events
	r.events = &EventStream{
		client:  nil,
		eventCh: make(chan *aegispb.EventInfo, 256),
		stopCh:  make(chan struct{}),
	}
	go func() {
		for e := range eventCh {
			select {
			case r.events.eventCh <- e:
			default:
				// channel full, skip
			}
		}
	}()

	return r
}

// Run 启动 REPL 主循环。
func (r *REPL) Run() {
	fmt.Println("  Aegis C2 Operator Console")
	fmt.Println("  Type 'help' for commands, 'exit' to quit")
	fmt.Println()

	// Refresh completer cache
	r.refreshCompleter()

	// Start event display goroutine
	go r.displayEvents()

	for {
		input, err := r.line.Prompt(r.prompt)
		if err != nil {
			break // EOF or Ctrl-C
		}

		trimmed := strings.TrimSpace(input)
		if trimmed == "" {
			continue
		}

		r.line.AppendHistory(trimmed)

		if trimmed == "exit" || trimmed == "quit" {
			fmt.Println("  bye.")
			break
		}

		if err := dispatch(r.client, trimmed); err != nil {
			fmt.Printf("  error: %v\n", err)
		}
	}

	r.line.Close()
	r.events.Stop()
}

func (r *REPL) tabCompleter(line string) []string {
	return r.completer.complete(line)
}

func (r *REPL) displayEvents() {
	for {
		select {
		case <-r.events.stopCh:
			return
		case e := <-r.events.eventCh:
			// Print event above prompt using liner's AppendHistory-like output
			fmt.Printf("\n  >> [%s] %s", e.Type, ts(e.Timestamp))
			if e.AgentID != "" {
				fmt.Printf(" agent=%s", e.AgentID)
			}
			if e.TaskID != "" {
				fmt.Printf(" task=%s", e.TaskID)
			}
			fmt.Println()
			// Re-print prompt so user sees it after event
			fmt.Print(r.prompt)
		}
	}
}

func (r *REPL) refreshCompleter() {
	resp, err := r.client.ListAgents(ctx(), &aegispb.ListAgentsRequest{})
	if err == nil {
		var ids []string
		for _, a := range resp.Agents {
			ids = append(ids, a.ID)
		}
		r.completer.update(ids, nil)
	}

	// Also fetch profiles
	presp, err := r.client.ListProfiles(ctx(), &aegispb.ListProfilesRequest{})
	if err == nil {
		var names []string
		for _, p := range presp.Profiles {
			names = append(names, p.Name)
		}
		r.completer.update(nil, names)
	}
}
