//go:build windows

package extexec

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/moloch--/memmod"
)

// Extension represents an in-memory loaded DLL extension.
type Extension struct {
	ID     string
	module *memmod.Module
	mu     sync.Mutex
}

// Load loads a DLL from raw bytes into memory without touching disk.
// Returns an Extension handle for calling exports.
func Load(data []byte, id string) (*Extension, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("extension data is empty")
	}

	mod, err := memmod.LoadLibrary(data)
	if err != nil {
		return nil, fmt.Errorf("memmod.LoadLibrary: %w", err)
	}

	return &Extension{ID: id, module: mod}, nil
}

// Call executes an export function from the in-memory DLL.
// The export must follow the prototype: int Run(buffer *byte, bufferSize uint32, callback func(*byte, int) int)
// onFinish is called with the data returned by the DLL via the callback mechanism.
func (e *Extension) Call(export string, arguments []byte, onFinish func([]byte)) error {
	if e.module == nil {
		return fmt.Errorf("module not loaded")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	exportPtr, err := e.module.ProcAddressByName(export)
	if err != nil {
		return fmt.Errorf("export %q not found: %w", export, err)
	}

	callback := syscall.NewCallback(func(data uintptr, dataLen uintptr) uintptr {
		n := int(dataLen)
		if n > 0 && data != 0 {
			// Data is a valid pointer from the DLL callback — same pattern as Sliver's extension_windows.go
			outBytes := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(data))), n)
			dst := make([]byte, n)
			copy(dst, outBytes)
			if onFinish != nil {
				onFinish(dst)
			}
		}
		return 0
	})

	var argumentsPtr uintptr
	var argumentsSize uintptr
	if len(arguments) > 0 {
		argumentsPtr = uintptr(unsafe.Pointer(&arguments[0]))
		argumentsSize = uintptr(uint32(len(arguments)))
	}

	ret, _, errno := syscall.Syscall(exportPtr, 3, argumentsPtr, argumentsSize, callback)
	if ret != 0 && errno != 0 {
		return fmt.Errorf("export call failed: errno=%d", errno)
	}

	return nil
}

// Unload frees the in-memory module.
func (e *Extension) Unload() error {
	if e.module == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.module = nil
	return nil
}
