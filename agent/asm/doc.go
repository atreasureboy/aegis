// Package stub 提供间接 syscall 和调用栈欺骗的汇编 stub。
// 参考 Havoc payload/Demon/src/asm/Syscall.x64.asm 和 Spoof.x64.asm。
//
// 使用方法（Go amd64）：
//
// Go 支持在 .s 文件中使用 Go 汇编语法。
// 间接 syscall 需要：
// 1. 将 syscall number 放入 eax 寄存器
// 2. 设置 rcx, rdx, r8, r9（前 4 个参数）
// 3. 执行 syscall 指令
//
// Go 汇编不支持直接嵌入 .text 中的 shellcode，
// 因此完整的间接 syscall 实现需要：
// - CGO 模式：编写 C/asm 文件，通过 #cgo 编译
// - 纯 Go 模式：使用 runtime·cgocall 或 unsafe.Pointer 跳转
//
// Havoc 的实现（Syscall.x64.asm）：
// - SyscallStub: 接收 syscall number + 参数 → 设置寄存器 → syscall → ret
// - FindSsnOfHookedSyscall: 搜索相邻函数的 syscall number
//
// Havoc 的实现（Spoof.x64.asm）：
// - SpoofRetAddr: 将返回地址替换为合法 DLL 中的地址
// - 目的：EDR 检查调用栈时看到的是正常调用链
//
// CGO 编译要求：
// - 需要在 windows/amd64 平台使用 gcc/x86_64-w64-mingw32-gcc 交叉编译
// - asm 文件需通过 CGO_LDFLAGS 链接
package stub
