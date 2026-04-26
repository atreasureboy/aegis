package repl

import "strings"

// completer 提供 REPL 的 Tab 补全。
type completer struct {
	agentIDs     []string
	profileNames []string
}

// newCompleter 创建补全引擎。
func newCompleter() *completer {
	return &completer{}
}

// update 从服务器数据刷新补全缓存。
func (c *completer) update(agentIDs, profileNames []string) {
	if agentIDs != nil {
		c.agentIDs = agentIDs
	}
	if profileNames != nil {
		c.profileNames = profileNames
	}
}

// complete 根据当前输入行和光标位置返回补全候选。
func (c *completer) complete(line string) []string {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return c.allCommands()
	}

	cmd := parts[0]
	args := parts[1:]

	// 补全命令名
	if len(parts) == 1 && !strings.HasSuffix(line, " ") {
		var completions []string
		for _, cc := range c.allCommands() {
			if strings.HasPrefix(cc, cmd) {
				completions = append(completions, cc+" ")
			}
		}
		return completions
	}

	// 补全 agent ID
	switch cmd {
	case "agent", "task", "kill", "tasks", "loot":
		if len(args) == 1 {
			return c.matchPrefix(args[0], c.agentIDs)
		}
	case "profile", "profile set":
		if len(args) <= 2 {
			return c.matchPrefix(args[len(args)-1], c.profileNames)
		}
	}

	// 子命令补全
	if len(args) == 0 && strings.HasSuffix(line, " ") {
		switch cmd {
		case "profile":
			return []string{"set ", "list "}
		case "listener":
			return []string{"start ", "stop ", "list "}
		case "server":
			return []string{"info "}
		}
	}

	return nil
}

func (c *completer) allCommands() []string {
	return []string{
		"agents ", "agent ",
		"task ", "kill ",
		"tasks ",
		"listeners ", "listener ",
		"operators ", "register-operator ",
		"profiles ", "profile ",
		"server ",
		"generate ",
		"loot ",
		"events ",
		"exit ", "quit ",
		"help ",
	}
}

func (c *completer) matchPrefix(prefix string, candidates []string) []string {
	var matched []string
	for _, cc := range candidates {
		if strings.HasPrefix(cc, prefix) {
			matched = append(matched, cc)
		}
	}
	return matched
}
