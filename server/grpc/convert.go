// Type conversion helpers: domain types → proto types.
package grpcsrv

import (
	"fmt"
	"net"

	"github.com/aegis-c2/aegis/proto/aegispb"
	"github.com/aegis-c2/aegis/server/event"
	"github.com/aegis-c2/aegis/server/listener"
	op "github.com/aegis-c2/aegis/server/operator"
	"github.com/aegis-c2/aegis/shared/types"
)

func toProtoAgent(a *types.Agent) *aegispb.AgentInfo {
	if a == nil {
		return nil
	}
	return &aegispb.AgentInfo{
		ID:            a.ID,
		Hostname:      a.Hostname,
		OS:            a.OS,
		Arch:          a.Arch,
		Username:      a.Username,
		PID:           int32(a.PID),
		IP:            a.IP,
		State:         string(a.State),
		FirstSeen:     a.FirstSeen.Unix(),
		LastHeartbeat: a.LastHeartbeat.Unix(),
		FailCount:     int32(a.FailCount),
		ProfileName:   a.ProfileName,
		Transport:     a.TransportType,
	}
}

func toProtoTask(t *types.Task) *aegispb.TaskInfo {
	if t == nil {
		return nil
	}
	result := ""
	exitCode := int32(0)
	duration := ""
	if t.Result != nil {
		result = string(t.Result.Stdout)
		if len(t.Result.Stderr) > 0 {
			result += "\n" + string(t.Result.Stderr)
		}
		exitCode = int32(t.Result.ExitCode)
		if t.Result.Duration > 0 {
			duration = t.Result.Duration.String()
		}
	}
	return &aegispb.TaskInfo{
		ID:        t.ID,
		AgentID:   t.AgentID,
		Command:   t.Command,
		Args:      t.Args,
		Status:    t.Status,
		Priority:  int32(t.Priority),
		CreatedAt: t.CreatedAt.Unix(),
		AuditTag:  t.AuditTag,
		Result:    result,
		ExitCode:  exitCode,
		Duration:  duration,
	}
}

func toProtoEvent(e *event.Event) *aegispb.EventInfo {
	if e == nil {
		return nil
	}
	data := make(map[string]string, len(e.Data))
	for k, v := range e.Data {
		if s, ok := v.(string); ok {
			data[k] = s
		} else {
			data[k] = fmt.Sprintf("%v", v)
		}
	}
	return &aegispb.EventInfo{
		ID:        e.ID,
		Type:      string(e.Type),
		Timestamp: e.Timestamp.Unix(),
		AgentID:   e.AgentID,
		TaskID:    e.TaskID,
		Source:    e.Source,
		Data:      data,
	}
}

func toProtoOperator(o *op.Operator) *aegispb.OperatorInfo {
	if o == nil {
		return nil
	}
	return &aegispb.OperatorInfo{
		ID:        o.ID,
		Name:      o.Name,
		Role:      string(o.Role),
		Connected: o.Connected,
		LastSeen:  o.LastSeen.Unix(),
		IPAddress: o.IPAddress,
	}
}

func toProtoListener(l *listener.Listener) *aegispb.ListenerInfo {
	if l == nil {
		return nil
	}
	bindAddr := l.Config["bind_addr"]
	host := bindAddr
	port := 0
	if p, ok := l.Config["port"]; ok {
		fmt.Sscanf(p, "%d", &port)
	}
	// Strip port from host to avoid duplication with the Port field
	if h, _, err := net.SplitHostPort(bindAddr); err == nil {
		host = h
	}
	return &aegispb.ListenerInfo{
		ID:       l.ID,
		Name:     l.Name,
		Protocol: string(l.Type),
		Host:     host,
		Port:     int32(port),
		Running:  l.Running,
	}
}
