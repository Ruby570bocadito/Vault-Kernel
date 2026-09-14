# vault_kernel — Architecture Decision Record (ADR)

> ruby570bocadito © 2026
> Versión: 3.1.0
> Fecha: 2026-05-18 (v3.0) · 2026-09-11 (v3.1)

---

> **Nota v3.3 (2026-09-13):** revisión de laboratorio del documento original.
> Se corrigen referencias obsoletas (deps de Go, matriz de CI) y se registran los
> hallazgos de v3.3: conflicto de `sys_call_table` con headers modernos, UAF en
> `call_usermodehelper`, y dropper/C stager regenerados con tests
> (`tests/test_payloads.sh`). Ver `CHANGELOG.md`.

> **Nota v3.4/v3.5 (2026-09-15):** rondas de mantenimiento del agente único.
> Se cierran todos los bugs B01–B07 de la sección 6 (estado real verificado
> contra el código) y se añaden los ADR 13–15 (filtro dirent con memmove,
> truncamiento seguro de reportes ioctl, iteración getdents hasta EOF real).
> Ver `CHANGELOG.md` y `docs/agentes/`.

## 1. Stack Tecnológico

### Decisión: Kernel Module en C, Userland Client en Go, Build en Make + Docker

| Componente | Tecnología | Justificación |
|-----------|-----------|---------------|
| **Kernel Module** | **C (GNU99)** | Única opción viable. El kernel Linux solo acepta módulos en C (Rust for Linux es experimental). C es el estándar en todos los rootkits de referencia (Diamorphine, Reptile, Suterusu, KoviD). |
| **Userland Client** | **Go 1.21+** | Single binary sin runtime externo, compilación cruzada nativa, manejo de ioctl vía `syscall.Syscall(SYS_IOCTL, ...)` nativo (cero dependencias externas). Go es el estándar de facto en tooling de red team (Sliver C2, Merlin, Cobalt Strike BOF tooling). |
| **Build System** | **Make + Kbuild** | Make es el build system estándar del kernel. Kbuild maneja dependencias de headers automáticamente. Simple, universal, sin dependencias extra. |
| **Containerización** | **Docker + Compose** | Entorno de build reproducible con kernel headers exactos. Docker Compose para simular entornos multi-nodo (C2 ↔ víctimas). |
| **Testing** | **Go testing + Bash + Python** | Unit tests en Go para el cliente. Integration tests en Bash para ioctl. Python para pentesting automatizado. |
| **CI/CD** | **GitHub Actions** | Build multi-kernel real: headers del runner + matriz Docker (5.15, 6.8). Tests automatizados en cada push. |

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

## 6. Bugs Identificados — estado de cierre (revisión v3.5, 2026-09-15)

Todos los bugs de esta lista histórica (v3.0) están cerrados; se conserva el
registro con la evidencia de cierre verificada contra el código actual:

| ID | Severidad | Estado | Evidencia de cierre |
|----|-----------|--------|---------------------|
| B01 | Medium | ✅ Cerrado (v3.1) | `vault_kernel_class` es `static` solo en `ioctl.c`; `core.h` no lo declara extern |
| B02 | High | ✅ Cerrado (v3.4) | Reportes `LIST_HIDDEN` vía `vk_snprint()` con clamp de truncamiento (ADR 14); el bug que v3.0 detectó y el que v3.3 reintrodujo con `p += snprintf` quedan cubiertos |
| B03 | Medium | ✅ Cerrado (v3.3) | `fdput(f)` se ejecuta incondicionalmente tras evaluar el file con la referencia viva |
| B04 | Low | ✅ Cerrado (v3.1) | `get_proc_inode()` solo corre en `net_hide_init()` (contexto de proceso, durmible) |
| B05 | Medium | ✅ Cerrado (v3.1) | El substring match solo aplica cuando el patrón oculto contiene `/` (path-based, intencional y documentado en `should_hide_file`) |
| B06 | High | ✅ Cerrado (v3.1) | `synchronize_rcu()` presente al final de `hooking_cleanup()` |
| B07 | Medium | ✅ Cerrado (v3.1) | `class_create()` bajo `LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)` en `ioctl_init()` |

Bugs abiertos actuales se rastrean en `docs/agentes/z_bugs/` (sección
"detectados pero no corregidos" de cada ronda).

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


---

## 9. v3.1 — Corrección del ABI de syscalls (pt_regs)

**Fecha:** 2026-09-11 · **Estado:** Aceptado e implementado

**Contexto.** Desde Linux 4.17 (x86_64), las entradas de `sys_call_table` apuntan a stubs `__x64_sys_*` que reciben un único `struct pt_regs *`; los parámetros reales viven en `regs->di/si/dx/r10/r8/r9`. El módulo v3.0 declaraba los hooks con la ABI antigua de argumentos directos, por lo que en **todos** los kernels anunciados como soportados los hooks leían basura (el puntero pt_regs como `fd`, registros residuales como path...).

**Decisión.**
- Implementar exclusivamente la ABI `pt_regs`: cada hook extrae sus argumentos de `regs` y llama al original con el mismo `regs` (patrón Diamorphine).
- El compilador **rechaza** kernels < 4.17 con `#error` en lugar de corromper silenciosamente. `PTREGS_SYSCALL_STUBS` se auto-define si `CONFIG_X86_64` y versión ≥ 4.17.

**Consecuencias.** Compatibilidad real 4.17–6.x en x86_64; el código de la ABI antigua (nunca compilable en kernels modernos) desaparece; los tests de CI compilan el `.ko` real contra los headers del runner.

---

## 10. v3.1 — Escalada de privilegios correcta (self vs PID remoto)

**Fecha:** 2026-09-11 · **Estado:** Aceptado e implementado

**Contexto.** `prepare_creds()`/`commit_creds()` operan sobre `current`: el v3.0 daba root al **caller** del ioctl aunque se pidiera otro PID, y además leía `task->comm` tras `put_pid()` (use-after-free).

**Decisión.** Dos rutas:
- **self** (pid ≤ 0 o propio): `prepare_creds()` + mutación + `commit_creds()` — el camino canónico del kernel.
- **remoto**: `get_task_struct()` bajo RCU, mutación **in-place** del `struct cred` del objetivo bajo `task_lock()` (sin swap de punteros → sin credenciales filtradas ni carreras con lectores RCU), lectura de `comm` con la referencia viva, `put_task_struct()`.

**Consecuencias.** `give-root <pid>` funciona de verdad; no hay UAF; los threads del objetivo (que comparten `cred`) se convierten en root de forma consistente.

---

## 11. v3.1 — Backdoor de palabra mágica funcional (señal 35 + FNV-1a)

**Fecha:** 2026-09-11 · **Estado:** Aceptado e implementado

**Contexto.** Tres bugs encadenados: (1) el kernel compara `SIGRTMIN`=32, pero glibc mapea `SIGRTMIN` a 34 → el `kill()` del usuario llega como **35**; el chequeo contra 33 jamás coincidía. (2) La palabra configurada por ioctl nunca se consultaba. (3) El usuario no tenía forma de calcular el PID codificado.

**Decisión.**
- `MAGIC_SIGNAL = 35` explícito, documentado y sincronizado con las constantes `MagicSignal` del CLI Go y del CLI Python (con test de unidad que fija el valor).
- El trigger exige `pid & 0xFFFF == fnv1a16(magic_str)` (FNV-1a 32-bit plegado a 16) y `pid >> 16 == puerto`. Implementación idéntica en C, Go y Python, con vectores de test.
- Nuevo comando `magic-encode <word> <port>` que imprime el `kill -s 35 <pid>` listo para disparar.

**Consecuencias.** El backdoor es disparable y reproducible; cada lenguaje puede generar el trigger sin conocer el resto.

---

## 12. v3.1 — Eliminación del hook write + observabilidad (GET_STATS)

**Fecha:** 2026-09-11 · **Estado:** Aceptado e implementado

**Contexto.** `hooked_write` era passthrough puro: interceptaba **todo** `write()` del sistema para devolver la llamada original — overhead global y superficie de detección sin ninguna función. En paralelo, el módulo no ofrecía forma de inspeccionar su estado en caliente.

**Decisión.**
- Eliminar el hook de `write` (6 hooks con propósito real).
- Añadir `IOCTL_GET_STATS (0x0F)`: versión, hooks instalados/planificados, flag de ocultación, contadores de objetos ocultos, bytes del keylogger y uptime. El reporte se construye en **heap** (el `kbuf[4096]` en stack del kernel era riesgo de desbordamiento) y `LIST_HIDDEN` también.

**Consecuencias.** Menos hooks = menos ruido; `vault_kernel stats` da observabilidad en operaciones de laboratorio; cero buffers de 4 KiB en stack.

---

## 13. v3.4 — Filtro dirent con desplazamiento real (memmove), no absorción

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** El filtro de v3.3 "absorbía" la entrada oculta en la entrada
conservada previa (creciendo su `d_reclen`) pero no contaba esos bytes en el
largo devuelto, y no eliminaba la entrada si no había predecesor conservado.
Salvo que la entrada oculta fuese la última del lote, el listado quedaba
truncado/corrupto o el fichero oculto seguía visible. Verificado con arnés
en espacio de usuario: 1/6 casos correctos.

**Decisión.** Las entradas conservadas se desplazan al frente del buffer con
`memmove` y el largo devuelto es la suma exacta de los registros válidos.
Los `d_off` desplazados conservan su valor original (misma elección que
Diamorphine; irrelevante para `readdir()` porque la enumeración la retoma el
kernel desde `file->f_pos`). Arnés propio: 6/6 casos (primera/media/última/
intercalada/dobles/ninguna).

**Consecuencias.** La ocultación es correcta en cualquier posición; los
tests de integración 2b (posiciones) y 2c (lista >4 KiB) protegen la
regresión en VM.

---

## 14. v3.4 — Truncamiento seguro de reportes ioctl (vk_snprint)

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** `p += snprintf(p, remaining, …)` con truncamiento hace
avanzar `p` más allá del buffer y underflowea `remaining` (size_t) →
escritura OOB en heap del kernel con ~16 ficheros ocultos de 255 chars.

**Decisión.** Wrapper `vk_snprint()` que clamp del truncamiento
(`w >= remaining → remaining-1`); todo reporte de `LIST_HIDDEN` pasa por él.
Los arneses de verificación viven fuera del repo (`scripts/`) para no mezclar
herramienta de auditoría con producto.

**Consecuencias.** El reporte se corta de forma segura; el patrón peligroso
queda proscrito (recomendación de seguridad para rondas futuras).

---

## 15. v3.5 — getdents itera hasta EOF real cuando una tanda completa está oculta

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** Al ocultar, si TODA la tanda devuelta por el `getdents`
original estaba compuesta de entradas ocultas, el hook devolvía 0 (EOF):
el proceso dejaba de ver ficheros visibles en tandas posteriores del mismo
directorio (truncamiento silencioso).

**Decisión.** Los hooks `getdents64`/`getdents` iteran: mientras el original
devuelva tandas y el filtro las deje a cero, se solicita la siguiente tanda
(`file->f_pos` ya avanzó). Se devuelve 0 solo con EOF real del directorio.
Verificado con arnés de flujo multi-tanda.

**Consecuencias.** Un directorio con ficheros ocultos y visibles mezclados
muestra exactamente los visibles, sin cortes; el caso "todo el directorio
oculto" sigue devolviendo EOF (comportamiento intencionado).
