# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
El versionado del módulo vive en `src/core.h` (`VAULT_KERNEL_VERSION`); el CLI
Go y el generador de payloads lo replican.

---

## [3.5] — 2026-09-15

Ronda 2 del agente único. Prioridad: **poner la CI en verde** (fallo
preexistente del job de payloads, también rojo en v3.3), cerrar el EOF
prematuro de `getdents` y añadir controles de verificación en VM.

### Corregido

| # | Bug | Fix |
|---|-----|-----|
| 1 | **CI en rojo desde v3.3** (job "Payload regression"): el stager C generado ignoraba el valor de retorno de `write()` → `-Wunused-result` con la glibc fortificada de Ubuntu (no reproducible con gcc sin FORTIFY, por eso pasaba en local) | El stager comprueba `write(fd, data, len) != (ssize_t)len` y aborta con `perror` — un write corto corrompía el `.ko`; verificado compilando con `-D_FORTIFY_SOURCE=2`: cero warnings |
| 2 | `getdents64`/`getdents` devolvían **EOF prematuro** cuando TODA una tanda estaba compuesta de entradas ocultas: el proceso dejaba de ver ficheros visibles de tandas posteriores del mismo directorio | Los hooks iteran: mientras el original devuelva tandas filtradas a cero, piden la siguiente (`file->f_pos` ya avanzó); EOF solo con el fin real del directorio. Arnés multi-tanda: viejo 1/3 visibles, nuevo 3/3, y "todo oculto" sigue devolviendo EOF |
| 3 | CLIs de 32 bits sobre kernel de 64 recibían `ENOTTY` | `.compat_ioctl = vault_kernel_ioctl` — todos los comandos pasan buffers de tamaño fijo, el puntero compat zero-extended llega al mismo handler |

### Añadido

- **`stats --json`** (Go y Python): el reporte `GET_STATS` reemitido como JSON con números convertidos — consumible por scripts de lab sin text-munging.
- **`keylog --follow [ms]`** (Go y Python): stream en vivo del keylogger con diff de sufijo entre polls (replay completo al envolver el buffer), Ctrl-C para terminar.
- **Tests de integración nuevos** (VM): 2b "File hiding — first/middle/last of the dirent batch" (regresión del filtro v3.4) y 2c "List with oversized hide-list" (regresión del truncamiento v3.4, 20 entradas de 250 chars sobre el reporte de 4 KiB).

### Documentación

- `docs/ADR.md`: cerrada la lista histórica B01–B07 con evidencia de cierre verificada, y añadidos los ADR 13 (filtro dirent memmove), 14 (vk_snprint) y 15 (getdents multi-tanda).
- README: `stats --json` y `keylog --follow` documentados.
## [3.4] — 2026-09-15

Ronda de mantenimiento del agente único (Director → Implementaciones →
Pulimiento → Bugs/Seguridad). Dos bugs críticos de kernel corregidos con
verificación, hardening del canal de control y mejoras de producto para
lab.

### Corregido — kernel (críticos)

| # | Bug | Fix |
|---|-----|-----|
| 1 | `filter_dirents()` (file_hide.c) absorbe la entrada oculta en la entrada previa pero **no suma esos bytes** al largo devuelto, y **nunca elimina** una entrada oculta sin predecesor conservado → salvo que la entrada oculta fuese la última del lote: primera posición = fichero **seguía visible**; cualquier otra = listado **truncado/corrupto** y `ls` parseando memoria obsoleta | Reescrito con desplazamiento real (`memmove`) de las entradas conservadas al frente del buffer; el largo devuelto es ahora exacto. Validado con arnés en espacio de usuario sobre buffers dirent sintéticos: 6/6 casos (primero/medio/último/intercalado/ninguno/dobles) frente a 1/6 del algoritmo viejo |
| 2 | `IOCTL_LIST_HIDDEN` (ioctl.c) usaba `p += snprintf(...)` — al truncar, `snprintf` devuelve el largo que *quería* escribir: `p` se salía de la asignación y `remaining` underfloweaba a un `size_t` enorme, pasando el guardia `remaining > 64` → **escritura fuera de límites en el heap del kernel** con ~16 ficheros ocultos de 255 chars | Wrapper `vk_snprint()` que trunca con clamp y mantiene `p`/`remaining` siempre dentro del buffer; el reporte se corta de forma segura |

### Corregido — kernel (medios)

| # | Bug | Fix |
|---|-----|-----|
| 3 | `hooked_read()` filtraba **cualquier** fichero cuyo dentry se llamase `tcp`/`tcp6`/`udp`/`udp6` (p. ej. `./tcp` del cwd) mientras hubiera puertos ocultos — falso positivo con pérdida de datos para el usuario | `is_proc_net_file()` exige además `s_magic == PROC_SUPER_MAGIC`: solo procfs real se filtra |
| 4 | Mensaje de error de compilación con referencia de versión obsoleta ("v3.1") | Texto genérico sin versión |

### Seguridad

- **Canal de control con gate de capacidades**: `vault_kernel_open()` exige `CAP_SYS_ADMIN` — hasta ahora el módulo confiaba en el modo del nodo (`0600 root:root` vía devtmpfs); una regla udev, un bind-mount de contenedor o un quirk de distro que aflojara los permisos permitiría a **cualquier usuario local** pedir `IOCTL_GIVE_ROOT`. Ahora el módulo lo comprueba él mismo (`-EPERM`).
- **Validación de entrada en ambos CLI**: nombres de fichero > 255 bytes, palabra mágica > 15 chars y target de shell > 255 bytes se rechazan con error claro en vez de truncarse en silencio contra los buffers fijos del kernel.

### Añadido

- **Comando `doctor`** (Go y Python, paridad total): diagnóstico de lab en un solo paso — existencia y modo del nodo, apertura RW, respuesta de `GET_STATS`, match de versión cliente/módulo, hooks instalados, estado stealth (`/sys/module`), e interfaces keylog/list. Salida no-cero solo si el módulo es inalcanzable.
- **`give-root` con verificación**: tras el ioctl, el CLI comprueba `euid=0` (self, el ioctl corre en el propio task) o lee `Uid:` de `/proc/<pid>/status` (remoto) y lo reporta.
- **`docs/DETECTION.md`**: guía de detección para blue teams — IOC concretos (nodo `/dev/vault_kernel`, logs `[vault_kernel]`, unidad `dbus-system.service`, firma `kill(pid, 35)` con pid imposible), comprobaciones rápidas en vivo, verificación robusta (integridad de syscall table, notifier chains, forense con Volatility/LKRG) y endurecimiento preventivo (`module.sig_enforce`, `kptr_restrict`, reglas auditd).
- **`make test-payloads`** y `make test` ejecuta Go + payloads de una vez.

### Limpieza

- Código muerto eliminado: `is_file_hidden()` (definida y declarada, sin llamadas), macro `MAX_HOOKS` (sin uso) y declaración sobrante de `is_pid_hidden()` en `core.h` (solo se usa dentro de `proc_hide.c`).
- README: comando `doctor` documentado, sección "Detección (para blue teams)" nueva, estructura actualizada con `docs/DETECTION.md` y `docs/agentes/`.

## [3.3] — 2026-09-13

Pase de auditoría y **verificación en laboratorio**: todo lo que anunciaba
v3.2 se compiló, se testeó y se corrigió de verdad. Los hallazgos clave
demuestran que partes del código anterior eran "simuladas": parecían
funcionales pero nunca se habían ejecutado.

### Corregido — kernel

| # | Bug | Fix |
|---|-----|-----|
| 1 | `unsigned long *sys_call_table` colisionaba con la declaración del kernel (`asm/syscall.h`, incluida por `linux/module.h` en kernels modernos) → **el módulo no compilaba en Debian** ni en headers ≥ ~5.18 | Renombrado a `vk_sys_call_table` (espaciado de nombres del módulo) |
| 2 | `reverse_shell_spawn()` pasaba `cmd[256]` del **stack** a `call_usermodehelper()` con `UMH_NO_WAIT` → use-after-free en kernel cuando el frame moría antes del exec | `UMH_WAIT_EXEC` (bloquea hasta que el execve consume argv) |
| 3 | `hooked_read()` hacía `fdget()` + strcmp del dentry en **cada** `read()` del sistema aunque no hubiera puertos ocultos | Fast-path: si `hidden_port_count == 0`, retorno antes de tocar la fd table |
| 4 | `register_keyboard_notifier()` sin chequear → unregister de un notifier nunca registrado si fallaba | Return value propagado; init falla limpio |

### Corregido — payloads (el "código simulado")

| # | Bug | Fix |
|---|-----|-----|
| 5 | **Dropper bash muerto al llegar**: la variable `T` se usaba para el workdir Y para el payload base64; `mkdir -p "$T"` expandía un blob de cientos de KB como nombre de directorio | Variables separadas: `WORKDIR` (directorio) y `PAYLOAD_B64` (datos) |
| 6 | Toda la cadena posterior del dropper (build, persistencia, ocultación) referenciaba `T` corrupto | Pipeline completo revisado y probado round-trip |
| 7 | C stager: `sscanf("%d")` no puede parsear `host:puerto` → puerto sin inicializar (basura o 80 silencioso) | Parser manual de `http://host[:port]/path` |
| 8 | C stager: si el header HTTP llegaba partido entre dos `read()`, los headers se incrustaban en el `.ko` descargado → módulo corrupto | Buffer de respuesta completo + un solo split `\r\n\r\n`; verificado **byte a byte** contra el `.ko` original |
| 9 | Unidad systemd de persistencia: el placeholder era igual que el delimitador del heredoc (`SVC`) | Placeholder `__KO_PATH__` no ambiguo |
| 10 | Clave XOR incrustada con interpolación directa → claves con comillas/backslashes rompían el python generado | Clave embebida como hex (`bytes.fromhex`) — cualquier clave es segura |

### Corregido — tooling

| # | Bug | Fix |
|---|-----|-----|
| 11 | `docker-compose.yml`: el builder ejecutaba `make` en `/build` (sin Makefile) → **el build Docker nunca funcionó** | `cd /build/src && make KERNEL=$(ls /lib/modules \| head -1)` |
| 12 | Dos compose files casi idénticos (`docker-compose.yml` + `docker-compose.test.yml`) con servicios desalineados | Un solo `docker-compose.yml` (builder + víctimas + atacante) |
| 13 | `make clean` en `src/` fallaba si no existían headers en `/lib/modules` (WSL2, CI parcial) | Guard `[ -d "$(KDIR)" ]` + borrado manual de artefactos |
| 14 | CLI Python: solo mapeaba `PermissionError`; dispositivo ausente o `ENOTTY` volcaban traceback | Helper `_ioctl()` con mapeo limpio de `OSError`; mensajes accionables; validación de puertos 1-65535 |

### Añadido

- **`tests/test_payloads.sh`** — 13 comprobaciones de regresión ejecutables en
  cualquier sitio (sin root, sin módulo): sintaxis del dropper, round-trip del
  tarball vs `src/`, claves XOR hostiles, compilación del C stager,
  `py_compile` del stager Python, paridad de ioctls con el cliente Go.
- **Dry-run de droppers**: `INSMOD=/bin/true bash dropper.sh` ejecuta todo el
  pipeline sin tocar el kernel (también en el C stager vía `getenv("INSMOD")`).
- Verificación local de compilación del `.ko` contra headers **6.1.0-50**
  (Debian bookworm) y **7.1.13** (Debian 14) — además de la matriz CI 5.15/6.8.
- Job de CI para los tests de payloads.
- `docs/ADR.md` (traslado de `brain/ADR.md`) con nota v3.3.

### Limpieza

- `brain/` eliminado: el log de sesión de desarrollo ya no forma parte del
  repositorio; el ADR vive en `docs/`.
- Changelogs históricos movidos del README a este fichero.
- `.gitignore`: `docker/out/`, payloads generados, scratch local.

---

## [3.2] — 2026-09-11

### Corregido

| # | Bug | Fix |
|---|-----|-----|
| 1 | `filter_dirents()`: un `d_reclen` corrupto (0) causaba bucle infinito en kernel | Guard `reclen == 0 \|\| cur + reclen > end → break` |
| 2 | `hooked_read`: inodos de `/proc/net/*` cacheados al cargar → el filtro moría en netns nuevos (contenedores) | Fallback por nombre de dentry en runtime, evaluado antes de `fdput()` |
| 3 | Gap de detección: `stat`/`lstat`/`find -stat` veían los ficheros ocultos | Nuevo hook `statx` → `-ENOENT` para rutas ocultas |
| 4 | Ficheros ocultos enumerados vía `statx` con `AT_EMPTY_PATH` | Pathname vacío pasa sin filtrar (no rompe `fstat`) |

### Añadido

- Hook `statx` (7º hook).
- `IOCTL_RESET_ALL` (0x10) + comando `reset` (Go y Python).
- Parámetro `auto_hide` en `insmod`.
- Matriz multi-kernel en CI contra headers 5.15 y 6.8.

---

## [3.1] — 2026-09-11

Reescritura de la ABI de syscalls y arreglos críticos verificados:

| # | Bug | Fix |
|---|-----|-----|
| 1 | Hooks con ABI pre-4.17 (args directos) → rotos en todos los kernels anunciados | Capa compat `pt_regs` (`regs->di/si/dx`); `< 4.17` no compila |
| 2 | `give-root <pid>` daba root al caller + UAF de `task->comm` | Ruta self (`commit_creds`) y ruta remota (mutación in-place bajo `task_lock`) |
| 3 | `net_hide` muerto: parseaba la IP y comparaba byte-order incorrecto | Parser por campos (local+remote), puertos en host order |
| 4 | `getdents64`: fuga de todas las entradas si el buffer entero estaba oculto | `kept == 0 → return 0` (EOF) |
| 5 | Señal mágica 33 del kernel ≠ 35 de glibc → el backdoor nunca disparaba | `MAGIC_SIGNAL 35` explícito, sincronizado con los CLIs |
| 6 | Palabra mágica guardada pero nunca usada | Trigger = `(port<<16) \| fnv1a16(word)`, idéntico en C/Go/Python |
| 7 | `kbuf[4096]` en stack del kernel + `copy_to_user` bajo spinlock | Buffers en heap; snapshot fuera del lock |
| 8 | `device_create` sin chequear `ERR_PTR` | `IS_ERR()` + propagación de error |
| 9 | Hook `write` passthrough global (overhead) | Eliminado |
| 10 | `((PASS++))` con `set -e` mataba integration.sh | `PASS=$((PASS+1))`, ANSI-C quoting |
| 11 | Sin CI | `.github/workflows/ci.yml` |
| 12 | Herencia de rename + unidad systemd inválida | Renombrado; `Type=oneshot` + `RemainAfterExit=yes` |

---

## [3.0] — 2026-05-18

Versión inicial con cliente Go, Docker build environment y Python CLI
legado. Detalles en `docs/ADR.md`.
