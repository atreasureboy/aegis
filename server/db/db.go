// Package db 提供 SQLite 数据库持久化层。
// 借鉴 Sliver 的数据库设计 (server/db/models/) — 使用 SQLite 存储 Agent、Task、Loot、Operator 等所有数据。
//
// 面试要点：
// 1. 为什么 C2 需要数据库：
//    - Agent 注册信息需要持久化（Server 重启后能恢复）
//    - Task 执行结果需要持久存储
//    - Loot/Credentials 需要安全存储
//    - 审计日志需要持久化查询
// 2. Sliver 使用 SQLite + GORM
// 3. Aegis 使用 SQLite + 原生 SQL（更轻量，无 ORM 依赖）
// 4. 安全考虑：数据库文件应加密存储（SQLCipher）
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB 是数据库连接。
type DB struct {
	conn *sql.DB
}

// Open 打开或创建数据库。
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// WAL mode for better concurrent read performance
	conn.Exec("PRAGMA journal_mode=WAL")
	conn.Exec("PRAGMA synchronous=NORMAL")
	conn.Exec("PRAGMA cache_size=-2000") // 2MB cache
	conn.Exec("PRAGMA busy_timeout=5000") // 5s busy timeout

	// SQLite 优化配置 (WAL mode allows some concurrent reads)
	conn.SetMaxOpenConns(4)  // Allow some concurrent reads (WAL mode supports this)
	conn.SetMaxIdleConns(4)
	conn.SetConnMaxLifetime(time.Hour)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

// Close 关闭数据库连接。
func (d *DB) Close() error {
	return d.conn.Close()
}

// migrate 创建所有表。
func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		id          TEXT PRIMARY KEY,
		hostname    TEXT NOT NULL,
		os          TEXT NOT NULL,
		arch        TEXT NOT NULL,
		username    TEXT,
		pid         INTEGER,
		uid         TEXT,
		interval    INTEGER NOT NULL DEFAULT 60,
		jitter      INTEGER NOT NULL DEFAULT 10,
		profile     TEXT,
		transport   TEXT NOT NULL DEFAULT 'http',
		state       TEXT NOT NULL DEFAULT 'offline',
		hostname_orig TEXT,
		first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		kill_date   DATETIME,
		os_info     TEXT
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id         TEXT PRIMARY KEY,
		agent_id   TEXT NOT NULL,
		command    TEXT NOT NULL,
		args       TEXT,
		state      TEXT NOT NULL DEFAULT 'pending',
		priority   INTEGER NOT NULL DEFAULT 0,
		result     TEXT,
		err        TEXT,
		exit_code  INTEGER DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (agent_id) REFERENCES agents(id)
	);

	CREATE TABLE IF NOT EXISTS loot (
		id          TEXT PRIMARY KEY,
		agent_id    TEXT NOT NULL,
		loot_type   TEXT NOT NULL,
		name        TEXT NOT NULL,
		filename    TEXT,
		size        INTEGER NOT NULL DEFAULT 0,
		file_path   TEXT,
		metadata    TEXT,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (agent_id) REFERENCES agents(id)
	);

	CREATE TABLE IF NOT EXISTS operators (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE,
		role        TEXT NOT NULL DEFAULT 'operator',
		api_key     TEXT NOT NULL UNIQUE,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_login  DATETIME
	);

	CREATE TABLE IF NOT EXISTS events (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		event_type  TEXT NOT NULL,
		agent_id    TEXT,
		task_id     TEXT,
		data        TEXT,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		operator    TEXT,
		action      TEXT NOT NULL,
		target      TEXT,
		details     TEXT,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS canaries (
		id          TEXT PRIMARY KEY,
		payload_id  TEXT NOT NULL,
		domain      TEXT NOT NULL UNIQUE,
		triggered   INTEGER NOT NULL DEFAULT 0,
		trigger_ip  TEXT,
		trigger_at  DATETIME,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS pivots (
		id          TEXT PRIMARY KEY,
		agent_id    TEXT NOT NULL,
		pivot_type  TEXT NOT NULL,
		bind_addr   TEXT NOT NULL,
		running     INTEGER NOT NULL DEFAULT 0,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (agent_id) REFERENCES agents(id)
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
	CREATE INDEX IF NOT EXISTS idx_loot_agent ON loot(agent_id);
	CREATE INDEX IF NOT EXISTS idx_loot_type ON loot(loot_type);
	CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
	CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
	`

	_, err := d.conn.Exec(schema)
	return err
}

// ─── Agent CRUD ───

// Agent 表示数据库中的一个 Agent。
type Agent struct {
	ID         string
	Hostname   string
	OS         string
	Arch       string
	Username   string
	PID        int
	UID        string
	Interval   int
	Jitter     int
	Profile    string
	Transport  string
	State      string
	FirstSeen  time.Time
	LastSeen   time.Time
	KillDate   *time.Time
	OSInfo     string
}

// CreateAgent 插入新的 Agent 记录。
func (d *DB) CreateAgent(a *Agent) error {
	_, err := d.conn.Exec(`
		INSERT INTO agents (id, hostname, os, arch, username, pid, uid, interval, jitter, profile, transport, state, os_info)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ID, a.Hostname, a.OS, a.Arch, a.Username, a.PID, a.UID, a.Interval, a.Jitter, a.Profile, a.Transport, a.State, a.OSInfo)
	return err
}

// UpdateAgent 更新 Agent 信息。
func (d *DB) UpdateAgent(a *Agent) error {
	_, err := d.conn.Exec(`
		UPDATE agents SET hostname=?, os=?, arch=?, username=?, pid=?, uid=?,
			interval=?, jitter=?, profile=?, transport=?, state=?, last_seen=CURRENT_TIMESTAMP,
			os_info=?, kill_date=?
		WHERE id=?
	`, a.Hostname, a.OS, a.Arch, a.Username, a.PID, a.UID, a.Interval, a.Jitter, a.Profile, a.Transport, a.State, a.OSInfo, a.KillDate, a.ID)
	return err
}

// UpdateAgentState 更新 Agent 状态和最后在线时间。
func (d *DB) UpdateAgentState(id, state string) error {
	_, err := d.conn.Exec(`UPDATE agents SET state=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, state, id)
	return err
}

// GetAgent 按 ID 获取 Agent。
func (d *DB) GetAgent(id string) (*Agent, error) {
	var a Agent
	err := d.conn.QueryRow(`
		SELECT id, hostname, os, arch, username, pid, uid, interval, jitter,
			profile, transport, state, first_seen, last_seen, os_info
		FROM agents WHERE id=?
	`, id).Scan(&a.ID, &a.Hostname, &a.OS, &a.Arch, &a.Username, &a.PID, &a.UID,
		&a.Interval, &a.Jitter, &a.Profile, &a.Transport, &a.State,
		&a.FirstSeen, &a.LastSeen, &a.OSInfo)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListAgents 列出所有 Agent。
func (d *DB) ListAgents() ([]*Agent, error) {
	rows, err := d.conn.Query(`
		SELECT id, hostname, os, arch, username, pid, uid, interval, jitter,
			profile, transport, state, first_seen, last_seen, os_info
		FROM agents ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.Arch, &a.Username, &a.PID, &a.UID,
			&a.Interval, &a.Jitter, &a.Profile, &a.Transport, &a.State,
			&a.FirstSeen, &a.LastSeen, &a.OSInfo); err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, nil
}

// DeleteAgent 删除 Agent 及其关联数据。
func (d *DB) DeleteAgent(id string) error {
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM tasks WHERE agent_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM loot WHERE agent_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM agents WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ─── Task CRUD ───

// Task 表示数据库中的一个任务。
type Task struct {
	ID        string
	AgentID   string
	Command   string
	Args      string
	State     string
	Priority  int
	Result    string
	Err       string
	ExitCode  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateTask 插入新任务。
func (d *DB) CreateTask(t *Task) error {
	_, err := d.conn.Exec(`
		INSERT INTO tasks (id, agent_id, command, args, state, priority)
		VALUES (?, ?, ?, ?, ?, ?)
	`, t.ID, t.AgentID, t.Command, t.Args, t.State, t.Priority)
	return err
}

// GetPendingTasks 获取指定 Agent 的待执行任务（按优先级排序）。
func (d *DB) GetPendingTasks(agentID string) ([]*Task, error) {
	rows, err := d.conn.Query(`
		SELECT id, agent_id, command, args, state, priority, created_at, updated_at
		FROM tasks WHERE agent_id=? AND state='pending'
		ORDER BY priority DESC, created_at ASC
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Command, &t.Args, &t.State, &t.Priority, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, &t)
	}
	return tasks, nil
}

// UpdateTaskResult 更新任务结果。
func (d *DB) UpdateTaskResult(id, result, errMsg string, exitCode int) error {
	_, err := d.conn.Exec(`
		UPDATE tasks SET state=?, result=?, err=?, exit_code=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?
	`, "completed", result, errMsg, exitCode, id)
	return err
}

// GetTask 按 ID 获取任务。
func (d *DB) GetTask(id string) (*Task, error) {
	var t Task
	err := d.conn.QueryRow(`
		SELECT id, agent_id, command, args, state, priority, result, err, exit_code,
			created_at, updated_at
		FROM tasks WHERE id=?
	`, id).Scan(&t.ID, &t.AgentID, &t.Command, &t.Args, &t.State, &t.Priority, &t.Result, &t.Err, &t.ExitCode, &t.CreatedAt, &t.UpdatedAt)
	return &t, err
}

// GetAllPendingTasks 获取所有 Agent 的待执行任务（用于 Server 重启恢复）。
func (d *DB) GetAllPendingTasks() ([]*Task, error) {
	rows, err := d.conn.Query(`
		SELECT id, agent_id, command, args, state, priority, created_at, updated_at
		FROM tasks WHERE state='pending'
		ORDER BY priority DESC, created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Command, &t.Args, &t.State, &t.Priority, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, &t)
	}
	return tasks, nil
}

// UpdateTaskState 更新任务状态（如 pending → dispatched）。
func (d *DB) UpdateTaskState(id, state string) error {
	_, err := d.conn.Exec(`UPDATE tasks SET state=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, state, id)
	return err
}

// ListTasks 列出任务（可按 Agent 和状态过滤）。
func (d *DB) ListTasks(agentID, state string) ([]*Task, error) {
	query := `SELECT id, agent_id, command, args, state, priority, result, err, exit_code, created_at, updated_at FROM tasks WHERE 1=1`
	args := []interface{}{}
	if agentID != "" {
		query += ` AND agent_id=?`
		args = append(args, agentID)
	}
	if state != "" {
		query += ` AND state=?`
		args = append(args, state)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Command, &t.Args, &t.State, &t.Priority, &t.Result, &t.Err, &t.ExitCode, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, &t)
	}
	return tasks, nil
}

// ─── Loot CRUD ───

// LootRecord 表示数据库中的一条 Loot 记录。
type LootRecord struct {
	ID        string
	AgentID   string
	LootType  string
	Name      string
	Filename  string
	Size      int64
	FilePath  string
	Metadata  string
	CreatedAt time.Time
}

// CreateLoot 插入 Loot 记录。
func (d *DB) CreateLoot(l *LootRecord) error {
	_, err := d.conn.Exec(`
		INSERT INTO loot (id, agent_id, loot_type, name, filename, size, file_path, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, l.ID, l.AgentID, l.LootType, l.Name, l.Filename, l.Size, l.FilePath, l.Metadata)
	return err
}

// ListLoot 列出 Loot（可按 Agent 和类型过滤）。
func (d *DB) ListLoot(agentID, lootType string) ([]*LootRecord, error) {
	query := `SELECT id, agent_id, loot_type, name, filename, size, file_path, metadata, created_at FROM loot WHERE 1=1`
	args := []interface{}{}
	if agentID != "" {
		query += ` AND agent_id=?`
		args = append(args, agentID)
	}
	if lootType != "" {
		query += ` AND loot_type=?`
		args = append(args, lootType)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*LootRecord
	for rows.Next() {
		var l LootRecord
		if err := rows.Scan(&l.ID, &l.AgentID, &l.LootType, &l.Name, &l.Filename, &l.Size, &l.FilePath, &l.Metadata, &l.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, &l)
	}
	return records, nil
}

// ─── Operator CRUD ───

// Operator 表示数据库中的一个操作符。
type Operator struct {
	ID        string
	Name      string
	Role      string
	APIKey    string
	CreatedAt time.Time
	LastLogin *time.Time
}

// CreateOperator 插入操作符。
func (d *DB) CreateOperator(o *Operator) error {
	_, err := d.conn.Exec(`
		INSERT INTO operators (id, name, role, api_key)
		VALUES (?, ?, ?, ?)
	`, o.ID, o.Name, o.Role, o.APIKey)
	return err
}

// GetOperatorByName 按名称查找操作符。
func (d *DB) GetOperatorByName(name string) (*Operator, error) {
	var o Operator
	err := d.conn.QueryRow(`
		SELECT id, name, role, api_key, created_at, last_login
		FROM operators WHERE name=?
	`, name).Scan(&o.ID, &o.Name, &o.Role, &o.APIKey, &o.CreatedAt, &o.LastLogin)
	return &o, err
}

// ListOperators 列出所有操作符。
func (d *DB) ListOperators() ([]*Operator, error) {
	rows, err := d.conn.Query(`SELECT id, name, role, api_key, created_at, last_login FROM operators`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []*Operator
	for rows.Next() {
		var o Operator
		if err := rows.Scan(&o.ID, &o.Name, &o.Role, &o.APIKey, &o.CreatedAt, &o.LastLogin); err != nil {
			return nil, err
		}
		ops = append(ops, &o)
	}
	return ops, nil
}

// ─── Event ───

// InsertEvent 插入事件记录。
func (d *DB) InsertEvent(eventType, agentID, taskID, data string) error {
	_, err := d.conn.Exec(`INSERT INTO events (event_type, agent_id, task_id, data) VALUES (?, ?, ?, ?)`, eventType, agentID, taskID, data)
	return err
}

// ListEvents 列出最近的事件。
func (d *DB) ListEvents(n int) ([]map[string]interface{}, error) {
	rows, err := d.conn.Query(`SELECT id, event_type, agent_id, task_id, data, created_at FROM events ORDER BY created_at DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id int
		var eventType, agentID, taskID, data, createdAt string
		if err := rows.Scan(&id, &eventType, &agentID, &taskID, &data, &createdAt); err != nil {
			return nil, err
		}
		events = append(events, map[string]interface{}{
			"id":          id,
			"event_type":  eventType,
			"agent_id":    agentID,
			"task_id":     taskID,
			"data":        data,
			"created_at":  createdAt,
		})
	}
	return events, nil
}

// ─── Audit ───

// InsertAudit 插入审计日志。
func (d *DB) InsertAudit(operator, action, target, details string) error {
	_, err := d.conn.Exec(`INSERT INTO audit_log (operator, action, target, details) VALUES (?, ?, ?, ?)`, operator, action, target, details)
	return err
}

// ListAudit 列出审计日志。
func (d *DB) ListAudit(n int) ([]map[string]interface{}, error) {
	rows, err := d.conn.Query(`SELECT id, operator, action, target, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int
		var operator, action, target, details, createdAt string
		if err := rows.Scan(&id, &operator, &action, &target, &details, &createdAt); err != nil {
			return nil, err
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"operator":   operator,
			"action":     action,
			"target":     target,
			"details":    details,
			"created_at": createdAt,
		})
	}
	return logs, nil
}

// ─── Canary ───

// CreateCanary 插入金丝雀记录。
func (d *DB) CreateCanary(id, payloadID, domain string) error {
	_, err := d.conn.Exec(`INSERT INTO canaries (id, payload_id, domain) VALUES (?, ?, ?)`, id, payloadID, domain)
	return err
}

// TriggerCanary 标记金丝雀已触发。
func (d *DB) TriggerCanary(id, triggerIP string) error {
	_, err := d.conn.Exec(`UPDATE canaries SET triggered=1, trigger_ip=?, trigger_at=CURRENT_TIMESTAMP WHERE id=?`, triggerIP, id)
	return err
}

// ListCanaries 列出所有金丝雀。
func (d *DB) ListCanaries() ([]map[string]interface{}, error) {
	rows, err := d.conn.Query(`SELECT id, payload_id, domain, triggered, trigger_ip, trigger_at, created_at FROM canaries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id, payloadID, domain string
		var triggered int
		var triggerIP, triggerAt, createdAt *string
		if err := rows.Scan(&id, &payloadID, &domain, &triggered, &triggerIP, &triggerAt, &createdAt); err != nil {
			return nil, err
		}
		r := map[string]interface{}{
			"id":         id,
			"payload_id": payloadID,
			"domain":     domain,
			"triggered":  triggered,
			"created_at": createdAt,
		}
		if triggerIP != nil {
			r["trigger_ip"] = *triggerIP
		}
		if triggerAt != nil {
			r["trigger_at"] = *triggerAt
		}
		result = append(result, r)
	}
	return result, nil
}
