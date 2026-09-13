# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
El versionado del módulo vive en `src/core.h` (`VAULT_KERNEL_VERSION`); el CLI
Go y el generador de payloads lo replican.

---

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
