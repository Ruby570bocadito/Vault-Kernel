# vault_kernel — Architecture Decision Record (ADR)

> ruby570bocadito © 2026
> Versión: 3.0.0
> Fecha: 2026-05-18

---

## 1. Stack Tecnológico

### Decisión: Kernel Module en C, Userland Client en Go, Build en Make + Docker

| Componente | Tecnología | Justificación |
|-----------|-----------|---------------|
| **Kernel Module** | **C (GNU99)** | Única opción viable. El kernel Linux solo acepta módulos en C (Rust for Linux es experimental). C es el estándar en todos los rootkits de referencia (Diamorphine, Reptile, Suterusu, KoviD). |
| **Userland Client** | **Go 1.26** | Single binary sin runtime externo, compilación cruzada nativa, manejo de ioctl vía `golang.org/x/sys/unix`, consistente con el proyecto BTY del autor. Go es el estándar de facto en tooling de red team (Sliver C2, Merlin, Cobalt Strike BOF tooling). |
| **Build System** | **Make + Kbuild** | Make es el build system estándar del kernel. Kbuild maneja dependencias de headers automáticamente. Simple, universal, sin dependencias extra. |
| **Containerización** | **Docker + Compose** | Entorno de build reproducible con kernel headers exactos. Docker Compose para simular entornos multi-nodo (C2 ↔ víctimas). |
| **Testing** | **Go testing + Bash + Python** | Unit tests en Go para el cliente. Integration tests en Bash para ioctl. Python para pentesting automatizado. |
| **CI/CD** | **GitHub Actions** | Build multi-kernel (5.4, 5.10, 5.15, 6.1, 6.6). Tests automatizados en cada PR. |

### Alternativas evaluadas y descartadas

| Opción | Motivo de descarte |
|--------|-------------------|
| Rust para el kernel module | `rust/kernel` inestable, cambia cada release, no usable en producción aún (2026). |
| Python para el client | Requiere runtime, no da single binary, menos portable. |
| CMake | Overkill para kernel modules. Kbuild es el estándar. |
| Vagrant | Más pesado que Docker. Para testing real de LKM se usará VM directa. |

---

## 2. Arquitectura del Sistema

```
┌──────────────────────────────────────────────┐
│                  USERLAND                      │
│                                                │
│  ┌──────────────┐    ioctl()     ┌───────────┐ │
│  │ vault_kernel CLI │◄──────────────►│ /dev/     │ │
│  │   (Go)       │                │ vault_kernel  │ │
│  └──────────────┘                └─────┬─────┘ │
│                                        │       │
├────────────────────────────────────────┼───────┤
│                  KERNEL                │       │
│                                        ▼       │
│  ┌─────────────────── char device ───────────┐ │
│  │ ioctl dispatch (ioctl.c)                  │ │
│  └──┬──────┬──────┬──────┬──────┬───────────┘ │
│     │      │      │      │      │              │
│     ▼      ▼      ▼      ▼      ▼              │
│  ┌────┐┌────┐┌────┐┌────┐┌────────┐          │
│  │file││proc││net ││key ││backdoor│          │
│  │hide││hide││hide││log │+ priv_ │          │
│  │    ││    ││    ││ger ││esc     │          │
│  └──┬─┘└──┬─┘└──┬─┘└────┘└────────┘          │
│     │     │     │                              │
│     └─────┼─────┘                              │
│           ▼                                     │
│  ┌──────────────────┐                          │
│  │ Syscall Hooking  │ (sys_call_table mods)    │
│  │ getdents64,      │                          │
│  │ getdents, openat,│                          │
│  │ read, kill, write│                          │
│  └──────────────────┘                          │
│                                                │
│  ┌──────────────────┐                          │
│  │ Stealth Layer    │ (list_del, kobject_del)  │
│  └──────────────────┘                          │
└────────────────────────────────────────────────┘
```

## 3. Syscall Hook Chain

Cada hook sigue este patrón:

```
Userland llama getdents64(fd, buf, count)
    │
    ▼
hooked_getdents64()           ◄── Nuestra función (en sys_call_table)
    ├─ orig = hooks[idx].original
    ├─ ret = orig(fd, buf, count)        ◄── Llamada real al kernel
    ├─ kmalloc(ret) + copy_from_user()    ◄── Copia a kernel-space
    ├─ Filtrar entradas (should_hide_file)
    ├─ Ajustar d_reclen para mantener integridad del dirent chain
    ├─ copy_to_user(buf, modified, new_len)
    └─ return new_len
```

### Syscalls hookeadas

| Syscall | NR (x86_64) | Hook Index | Propósito |
|---------|-------------|------------|-----------|
| `getdents64` | 217 | HOOKIDX_GETDENTS64 | Ocultar archivos/dirs + PIDs en /proc |
| `getdents` | 78 | HOOKIDX_GETDENTS | Compatibilidad 32-bit |
| `openat` | 257 | HOOKIDX_OPENAT | Bloquear acceso a archivos ocultos |
| `read` | 0 | HOOKIDX_READ | Filtrar /proc/net/* para ocultar puertos |
| `kill` | 62 | HOOKIDX_KILL | Interceptar magic packet backdoor |
| `write` | 1 | HOOKIDX_WRITE | Reservado (passthrough) |
| `unlinkat` | 263 | HOOKIDX_UNLINKAT | Prevenir borrado de archivos ocultos |

## 4. Decisiones Clave

### 4.1 sys_call_table discovery
- **Primario**: kprobe sobre `kallsyms_lookup_name` (kernels >= 5.7)
- **Fallback**: `kallsyms_lookup_name` directo (kernels < 5.7)
- **Último recurso**: Page scanning alrededor de `__x64_sys_close`

### 4.2 Write Protection Bypass
CR0 WP bit manipulation (`read_cr0`/`write_cr0`) — estándar en rootkits, más simple y fiable que `set_memory_rw()` que requiere exponer direcciones de página.

### 4.3 Stealth
`list_del(THIS_MODULE->list)` + `kobject_del(mkobj.kobj)` — técnica clásica de rootkits. Se restaura antes de `rmmod` para evitar kernel panic.

---

## 5. Módulos y Responsabilidades

| Archivo | Responsabilidad | Líneas |
|---------|----------------|--------|
| `main.c` | Init/exit, sys_call_table find, CR0 WP, hook install/remove, stub hooked_write | 266 |
| `core.h` | Headers, IOCTL constants, structs, declaraciones globales | 186 |
| `hooking.c` | Wrapper de instalación de hooks | 30 |
| `file_hide.c` | getdents64/getdents/openat/unlinkat hooks, file hiding | 257 |
| `proc_hide.c` | PID hiding, kill hook, magic packet interceptor | ~100 |
| `net_hide.c` | /proc/net filtering, read hook, port hiding | 202 |
| `keylogger.c` | Keyboard notifier, scancode→ASCII translation | ~135 |
| `backdoor.c` | Reverse shell workqueue, magic packet trigger | 116 |
| `priv_esc.c` | give_root via cred manipulation | ~40 |
| `stealth.c` | Module hiding/unhiding, list_del, kobject operations | 66 |
| `ioctl.c` | Char device /dev/vault_kernel, ioctl dispatch | 198 |
| `client/vault_kernel_cli.py` | Python CLI (será reemplazada por Go) | ~280 |

---

## 6. Bugs Identificados (por corregir)

| ID | Severidad | Archivo | Descripción |
|----|-----------|---------|-------------|
| B01 | Medium | `ioctl.c:8` vs `core.h:96` | `vault_kernel_class` declarado como `static` y `extern` simultáneamente — conflicto de linkage |
| B02 | High | `ioctl.c:71-82` | Buffer overflow en LIST_HIDDEN: `snprintf(p, 256, ...)` debe usar `sizeof(kbuf) - (p - kbuf)` |
| B03 | Medium | `net_hide.c:138-144` | `fdput(f)` no se llama si `f.file` es NULL (aunque `fdput` maneja NULL, falta la llamada) |
| B04 | Low | `net_hide.c:114` | `kern_path` puede dormir — no debería llamarse desde contexto atómico; init corre en contexto seguro |
| B05 | Medium | `file_hide.c:55` | `strstr(name, hidden_files[i])` causa falsos positivos — oculta todo archivo cuyo nombre contenga el string oculto |
| B06 | High | `hooking.c` | Falta `synchronize_rcu()` después de `remove_hook()` — race condition al descargar el módulo |
| B07 | Medium | `main.c` | `class_create()` firma incompatible con kernels < 6.4 |

---

## 7. Próximos Pasos

1. **Corregir bugs B01-B07** → estabilidad del kernel module
2. **Reescribir cliente en Go** → single binary profesional
3. **Crear Dockerfile de build** → entorno reproducible
4. **Escribir tests unitarios (Go)** → validar cliente
5. **Escribir tests de integración** → validar ioctl en VM
6. **Auditar fugas de memoria** → kmalloc/kfree balance
7. **Probar en 3 kernels distintos** → compatibilidad
8. **Documentar en /brain/session_*.md** → trazabilidad
