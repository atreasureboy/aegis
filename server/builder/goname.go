package builder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// RenameConfig 控制导入路径重命名。
type RenameConfig struct {
	ProjectRoot  string            // 项目根目录
	OldModule    string            // 旧模块路径（如 "github.com/aegis-c2/aegis"）
	NewModule    string            // 新模块路径（留空自动生成）
	DryRun       bool              // 仅预览不写入
	RenameGoMod  bool              // 是否同时重命名 go.mod 中的 module 声明
	ExcludeDirs  map[string]bool   // 排除的目录（如 "vendor", ".git"）
}

// RenameImports 遍历项目，重命名所有 Go 文件的导入路径。
// 借鉴 Sliver 的 goname 策略：
//   - 使用 go/ast 解析 AST，精确替换 import spec
//   - 避免简单的字符串替换导致误伤
//   - 保留原有格式和注释
//
// 示例：
//
//	RenameImports(&RenameConfig{
//	    ProjectRoot: "/path/to/project",
//	    OldModule:   "github.com/aegis-c2/aegis",
//	    NewModule:   "github.com/googleapis/internal/pkg7a3b",
//	})
func RenameImports(cfg *RenameConfig) error {
	if cfg.NewModule == "" {
		cfg.NewModule = genFakeModuleName()
	}
	if cfg.ExcludeDirs == nil {
		cfg.ExcludeDirs = map[string]bool{
			".git": true, "vendor": true, "node_modules": true,
		}
	}

	oldPrefix := cfg.OldModule
	newPrefix := cfg.NewModule

	var filesChanged int
	err := filepath.Walk(cfg.ProjectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if cfg.ExcludeDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// 解析 Go 文件
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil // 跳过无法解析的文件
		}

		modified := false

		// 重命名 import spec
		for _, imp := range node.Imports {
			oldPath := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(oldPath, oldPrefix) {
				newPath := newPrefix + oldPath[len(oldPrefix):]
				imp.Path.Value = `"` + newPath + `"`
				modified = true
			}
		}

		// 重命名 package 声明中的注释引用（如果有）
		// go/ast 已确保只修改 import spec，不碰代码

		if !modified {
			return nil
		}

		if cfg.DryRun {
			fmt.Printf("[dry-run] would rewrite imports in: %s\n", path)
			filesChanged++
			return nil
		}

		// 写回文件
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, node); err != nil {
			return fmt.Errorf("print AST: %w", err)
		}

		if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("write file: %w", err)
		}

		filesChanged++
		return nil
	})
	if err != nil {
		return err
	}

	// 重命名 go.mod
	if cfg.RenameGoMod {
		goModPath := filepath.Join(cfg.ProjectRoot, "go.mod")
		if err := renameGoMod(goModPath, newPrefix); err != nil {
			return fmt.Errorf("rewrite go.mod: %w", err)
		}
	}

	fmt.Printf("rewritten imports in %d files: %s -> %s\n",
		filesChanged, oldPrefix, newPrefix)
	return nil
}

// renameGoMod 重写 go.mod 中的 module 声明。
func renameGoMod(path, newModule string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "module ") {
			lines[i] = "module " + newModule
			break
		}
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// RandomProjectName 生成随机项目名称（用于 --name 参数）。
func RandomProjectName() string {
	buf := make([]byte, 6)
	rand.Read(buf)
	prefixes := []string{"svc", "svcutil", "agent", "helper", "service", "daemon", "worker", "client", "proxy", "relay"}
	suffixes := []string{"", "lib", "core", "base", "internal", "v2"}
	idx := int(buf[0]) % len(prefixes)
	sidx := int(buf[1]) % len(suffixes)
	hex := hex.EncodeToString(buf[2:])
	return prefixes[idx] + suffixes[sidx] + "-" + hex
}
