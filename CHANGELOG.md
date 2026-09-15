# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
El versionado del módulo vive en `src/core.h` (`VAULT_KERNEL_VERSION`); el CLI
Go y el generador de payloads lo replican.

---

## [3.9] — 2026-09-15

Ronda 6 del agente único. Prioridad: **producto de lab (evidencia y
persistencia de capturas) + cierre sistémico de la gramática de
argumentos**. La auditoría de la ronda construyó por primera vez una
matriz comando×cliente de gramáticas y encontró un patrón sistémico: el
dispatcher Go validaba "argumentos suficientes" pero nunca rechazaba el
EXCESO (15 de 20 cases ignoraban argumentos extra en silencio). El
módulo kernel no se toca (cuarta ronda consecutiva): estable desde v3.4.

### Añadido

- **Comando `capture`** (Go y Python): bundle de evidencia en un solo
  documento JSON — `stats` (misma conversión que `stats --json`) +
  `hidden` (misma forma que `list --json`) + `keylog` (buffer
  verbatim) + `captured_at` (UTC RFC3339 del snapshot) +
  `module_in_sysfs`. Builders puros espejo testados
  (`buildCaptureReport` / `build_capture_bundle`). Con `--out FILE` el
  fichero se crea 0600 (las capturas pueden contener pulsaciones) y se
  imprime un resumen de una línea; sin `--out`, el JSON va a stdout.
  Cuarto documento del contrato JSON — `docs/SCHEMAS.md` se
  reestructura por comando (docs/schemas/{stats,list,doctor,capture}.md),
  disparando la condición que dejó escrita el backlog de la ronda 5.
- **`keylog --output FILE`** (Go y Python): cada evento del stream (y
  la lectura one-shot) se añade TAMBIÉN a un fichero apéndice con
  flush+fsync por evento, como transcripción fiel de lo impreso en
  terminal (con marcas de tiempo si `--timestamps` está activo).
  Fichero creado 0600; el fichero solo se crea con el PRIMER registro
  (un buffer vacío no crea fichero, paridad exacta Go/Python).
  Gramática: `--output` con operand obligatorio, un solo uso, en
  cualquier posición; `--timestamps` sigue exigiendo `--follow`.
- **Autocompletado bash** (`completions/vault_kernel.bash`): cubre los
  DOS clientes (el binario Go y el CLI Python comparten superficie),
  completa comandos, flags por subcomando (`--json`, `--interval`,
  `--follow/--timestamps/--interval/--output`, `--out`) y rutas del
  filesystem para hide-file/unhide-file. Autocontenido: NO requiere el
  paquete bash-completion (solo `complete`/`compgen` builtin).
- **Test funcional de completions** (`tests/test_completions.sh`, 11
  checks): `bash -n`, registro de ambos binarios con `complete`,
  superficie de comandos de nivel 1, flags por comando, fallback a
  ficheros y ausencia de invención de flags en comandos posicionales.
  Nuevo job de CI `Bash completions (functional)` — CI pasa de 7 a 8
  jobs — y `make test`/`make test-completions`.
- **8 tests Go nuevos** (`TestParseKeylogArgsOutput`,
  `TestParseCaptureArgs`, `TestKeylogSink`, `TestBuildCaptureReport`,
  `TestParseWatchArgs`, `TestParseShellTarget`, `TestParsePIDArg`,
  `TestStrictArgs`) y **8 unittest Python nuevos** → 27 Go + 38 Python
  + 11 completions.

### Corregido

| # | Bug | Fix |
|---|-----|-----|
| 1 | **Gramática Go permisiva sistémica**: 15 de 20 cases del dispatcher ignoraban argumentos extra en silencio (`hide-file a b` ocultaba "a"; `watch --interval 500 extra`, `list extra`, `keylog-clear extra`...), mientras el CLI Python (argparse) los rechaza. Paridad rota en TODOS los caminos de error | Gramática estricta en todo el dispatcher: `parseWatchArgs` (pura, testeada), validación de operandos exactos y `--json`/`--out` únicos en doctor/list/stats/status/capture; helpers `expectExactArgs`/`rejectExtra` + tests. `status extra`/`version extra` también errores |
| 2 | **`shell` sin validación real de `ip:port`**: Go solo exigía "contiene `:`" (aceptaba `abc:def`; el kernel lo rechaba con EINVAL); Python no validaba NADA. El kernel era la única barrera | `parseShellTarget` (Go, pura + tests) y `_shell_target_arg` (Python): split en el ÚLTIMO `:`, host no vacío, puerto numérico 1-65535. IPv6 literal no soportado (el módulo parte en el primer `:`) — documentado en ambos |
| 3 | **`hide-pid`/`unhide-pid` aceptaban pid ≤ 0** en ambos clientes: el módulo añade cualquier int a la hide-list (`pid: -5` en `list`), entrada sin sentido; `hooked_kill` solo filtra pid > 0 | Validación cliente pid ≥ 1 en ambos (`parsePIDArg` Go + `_pid_arg` Python, testeada); el contrato del módulo no cambia |
| 4 | **`keylog` one-shot de Python con buffer VACÍO no imprimía NADA** (cur==prev=="" saltaba el print); Go imprime "[*] (no keystrokes captured)". Bug de paridad real arrastrado desde v3.5 | Camino one-shot reestructurado: imprime siempre (buffer o "(no keystrokes captured)"), el diff/sink vive solo en follow. Testeado |
| 5 | **README con conteos erróneos**: "17 ioctls/commands" ×2 (realidad: 16, 0x01–0x10) y "18 comandos" Go (realidad: 21) | Corregidos ambos; el árbol del README refleja completions/, tests/test_completions.sh y docs/schemas/ |

### Documentación

- **`docs/SCHEMAS.md`** pasa a índice de cuatro documentos con tablas
  por comando en `docs/schemas/{stats,list,doctor,capture}.md`
  (reestructuración condicionada del backlog v3.8). `capture.md` fija
  el orden contractual de las claves del envelope y la política 0600.
- **README**: `Novedades v3.9`, sección de comandos con `capture`,
  `keylog --output` y la nota de autocompletado, tree actualizado,
  badge/pie 3.9, `make test-completions` en Testing, CI 8 jobs.
- **ADR 19**: decisión de `capture` (evidencia, timestamp del snapshot,
  0600), `keylog --output` (transcripción fiel, apéndice, creación
  perezosa), política de autocompletado (autocontenida, dos clientes)
  y cierre de la política de gramáticas estrictas (todo parser puro +
  rechazo de exceso).

### Auditoría de la ronda

- CI 7/7 verde por API en `a26b364` (4ª ronda consecutiva) y suites
  locales 100% replicadas antes de tocar nada (23 Go, 30 Python, 13
  payloads, ruff, shellcheck, gofmt/vet/build, make).
- Matriz comando×cliente sistemática (hallazgo sistémico #1) y auditoría
  ABI 16/16/16 core.h↔Go↔Python por conteo.
- Falso positivo del canal de render de nuevo en la ayuda Go
  (`[ms]` aparentemente comido): verificado con grep -F que los bytes
  están completos ×3 en disco — la lección ADR 18 se aplica y se
  refuerza (verificar SIEMPRE bytes, nunca el render).
- El editor del agente convirtió TABs→espacios en el Makefile (2ª vez
  en 2 rondas): detectado por `make -n`, restaurado vía git checkout +
  re-aplicación con Python preservando \t. Política: editar el
  Makefile SOLO con scripts que preserven bytes.

## [3.8] — 2026-09-15

Ronda 5 del agente único. Prioridad: **paridad de los dos clientes y
contrato de salida**. La auditoría de la ronda re-verificó byte a byte
(esta vez con `od -c`, método definitivo) las dos sospechas que arrastraba
el canal de render del agente — los colores ANSI de los arneses de test y
la restauración del cursor en `watch` de Go — y confirmó que AMBAS están
correctas en disco: eran de nuevo artefactos de render, no del repo. El
bug real de la ronda es la validación del PID de `give-root` en Go. El
módulo kernel no se toca: estable desde v3.4.

### Añadido

- **`keylog --follow --timestamps`** (Go y Python): cada evento del
  stream se emite en línea nueva con la marca `[HH:MM:SS]` del sondeo
  que lo mostró (cota honesta: el buffer del módulo no lleva tiempo por
  pulsación). El formateo es una función pura — `formatKeylogEvent` /
  `format_keylog_event` — testeada en espejo en ambos clientes; sin
  `--timestamps` el comportamiento es byte-idéntico al de v3.7.
- **Comando `version` en el CLI Python** (paridad con Go, que lo tenía
  desde v3.6): `format_version_line()` replica el texto de
  `printVersion()` de Go — `vault_kernel CLI v3.8 (ioctl magic 0xC0,
  signal trigger 35)`.
- **`docs/SCHEMAS.md`**: contrato de los documentos JSON de `stats
  --json`, `list --json` y `doctor --json` — campos, tipos, reglas de
  presencia y política de versionado del campo `schema` (complementa
  ADR 17; cerraba el backlog de la ronda 4).
- **3 tests Go nuevos** (`TestParseGiveRootPID`, `TestParseKeylogArgs`,
  `TestFormatKeylogEvent`) y **6 unittest Python nuevos**
  (`TestFormatKeylogEvent`, `TestVersionCommand`) → 23 Go + 30 Python.

### Corregido

| # | Bug | Fix |
|---|-----|-----|
| 1 | **`give-root` Go ignoraba el error de `strconv.Atoi` del PID** (`pid, _`): un typo no numérico (`give-root abc`) se convertía en pid=0 → escalada **self** silenciosa, mientras el CLI Python la rechazaba como error de uso. Mismo comando, dos comportamientos según cliente | El parsing se extrae a `parseGiveRootPID()`: sin argumento (o pid<=0) sigue siendo "self" (contrato documentado del módulo), pero un argumento no numérico o argumentos extra son error de uso — paridad con `argparse type=int`. Testeado sin dispositivo |
| 2 | **`keylog` Go aceptaba argumentos desconocidos en silencio**: `keylog 500` (sin `--follow`) ignoraba el `500` y hacía la lectura one-shot; el intervalo posicional solo se validaba tras `--follow` | Gramática estricta en `parseKeylogArgs()`: flags `--follow`/`--timestamps` en cualquier orden, intervalo posicional solo tras `--follow` (mínimo 50), cualquier otro argumento es error de uso. `--timestamps` sin `--follow` es error en AMBOS clientes |

### Documentación e higiene

- **Bits de ejecución**: los 7 ficheros con shebang salen ahora
  ejecutables del repo (`tests/test_payloads.sh` ya lo estaba) —
  `./client/vault_kernel_cli.py status`, `./payloads/builder.sh`,
  `./tests/integration.sh` funcionan directamente; elimina los avisos
  `EXE001` de ruff.
- **`make help`** refleja los targets reales (`test-go`,
  `test-payloads`, `docker-test` no existían en la ayuda; la
  descripción de `test` databa de antes de la regresión de payloads).
- **`.gitignore`** añade `.ruff_cache/` explícito (hasta ahora solo
  estaba cubierto por el `.gitignore` interno del propio caché de
  ruff).
- **README**: `Novedades v3.8`, badge y pie 3.7 → 3.8, línea de
  `keylog --follow --timestamps` en la lista de comandos,
  `docs/SCHEMAS.md` en el árbol.
- Entrada **ADR 18**: paridad de superficie de comandos, semántica de
  `--timestamps` (marca del sondeo, no de la pulsación) y política de
  bits de ejecución.

### Auditoría de la ronda (verificaciones a nivel de bytes)

- Los colores ANSI de `tests/test_payloads.sh` y `tests/integration.sh`
  (`RED=$'\e[0;31m'`, etc.) están COMPLETOS en disco — la sospecha de
  esta ronda era un falso positivo del canal de render, que se come
  secuencias como `[0;31m` incluso dentro de salidas `repr()` de
  Python. `od -c` es el único verificador fiable.
- La restauración del cursor de `watch` en Go (`\x1b[?25h` en el
  `defer` de `runWatch`) está completa en disco — segunda verificación
  con `od -c`, mismo resultado.

---

## [3.7] — 2026-09-15

Ronda 4 del agente único. Prioridad: **producto del plano de control** —
la auditoría cerró el falso positivo recurrente de "corchetes
corruptos" (verificado a nivel de bytes: era un artefacto de render del
terminal del agente, no del repo), encontró un desajuste real de
paridad JSON en las rutas de fallo de `doctor --json` y completó dos
piezas del backlog (comando `watch`, esquemas versionados). El módulo
kernel no se toca: estable desde v3.4.

### Añadido

- **Comando `watch`** (Go y Python): vista en vivo de stats + listado
  de ocultos con refresco configurable (`--interval MS`, default 1000,
  mínimo 50, Ctrl-C para salir con restauración de cursor). El render
  es una función pura testeada en CI (`RenderWatchPanel` en
  `internal/vaultkernel`, `format_watch_panel` en el CLI Python) — el
  layout es un contrato fijado por tests espejo en ambos clientes.
- **Campo `"schema": 1`** en `stats --json`, `list --json` y
  `doctor --json` de ambos clientes: los scripts de lab pueden fijar
  `jq -e '.schema == 1'` y detectar cambios de formato en vez de
  fallar en silencio (ADR 17). Aditivo y compatible hacia atrás.
- **20 tests Go** (`watch_test.go`, `main_test.go`: envelope JSON con
  schema, paridad del documento doctor, panel de watch) y **24
  unittest Python** (panel de watch, `list --json` end-to-end, schema
  en stats/doctor, validación de `--interval`).

### Corregido

| # | Bug | Fix |
|---|-----|-----|
| 1 | **`doctor --json` divergente entre clientes en rutas de fallo**: el CLI Go declaraba `device_open`/`stats_responds` como `bool` con `omitempty` — la clave DESAPARECÍA del JSON justo cuando la comprobación fallaba; Python la emitía como `false`. Mismo comando, dos documentos según cliente y camino | En Go ambos campos pasan a `*bool` con asignación explícita en éxito y fallo (la semántica que ya tenían `keylog_responds`/`list_responds`): la clave aparece si la comprobación se ejecutó y solo desaparece si no llegó a ejecutarse — el contrato testado de Python. Verificado por `TestDoctorJSONEnvelopeParity` |
| 2 | **`--interval nan`/`inf` moría en runtime** (CLI Python): v3.6 aceptaba `float` y el valor no finito llegaba a `time.sleep()` → `ValueError`/`OverflowError` con traceback en vez de un error de uso. Los negativos se clampeaban en silencio | Validador `_ms_arg` para `keylog --interval` y `watch --interval`: enteros de texto, negativos rechazados, no finitos imposibles (`int("nan")` falla con mensaje claro). Tests `TestIntervalArgType` |

### Documentación

- README: `watch` en la lista de comandos, "Novedades v3.7", badge y
  pie a 3.7, y el conteo de jobs de CI de la sección inglesa corregido
  ("six jobs" → seven, databa de antes de la matriz Docker).
- ADR 17: envelope versionado + paridad de fallos + decisión de `watch`.
- CHANGELOG de la ronda 2 verificado a nivel de bytes: el typo del flag
  `--follow` con las unidades mangleadas que la ronda 3 "corrigió" ya
  estaba bien en disco (la "corrupción de corchetes" era un artefacto
  de render del terminal del agente; esta ronda lo confirma con conteo
  programático de corchetes en todo el repo — `ci.yml`, README,
  CHANGELOG y tests incluidos).

---

## [3.6] — 2026-09-15

Ronda 3 del agente único. Prioridad: **calidad del plano de control** —
la CI arrancaba 7/7 en verde por primera vez en la historia del repo y
la auditoría se movió al código cliente, donde destapó dos bugs reales
(con reproducción) y un hueco de cobertura (la CI de Python no
ejecutaba ningún test).

### Corregido

| # | Bug | Fix |
|---|-----|-----|
| 1 | **`stats --json` devolvía JSON corrupto** (regresión v3.5): el parser partía cada línea del reporte de `GET_STATS` por el primer `=`, y el módulo emite VARIOS pares por línea → perdía `version`, `hooks_planned`, `hidden_pids` y `hidden_ports` (4 de 10 claves; reproducido con el código real de ambos CLIs) | Parser por tokens compartido y testeado en los dos clientes (`ParseStatsReport`/`parse_stats_report`): se divide por espacios y después cada token en su primer `=`. Suite Go + 16 unittest Python en CI |
| 2 | **El check de versión de `doctor` nunca podía dispararse** (v3.4) y la línea de hooks se imprimía mangleada (`[ OK ] 7 hooks_planned=7/ syscall hooks…`) — mismo parser roto, `stats["version"]` quedaba vacío | Mismo fix: `doctor` usa el parser compartido; el aviso de desajuste cliente/módulo ya funciona y los contadores se muestran como números |
| 3 | **`keylog --follow --interval` dormía segundos en Python** (documentado y en Go: milisegundos) — `--interval 500` eran 8 minutos por poll, 1000x más lento | `_interval_ms_to_seconds()` con suelo de 50 ms, paridad Go/Python y tests de unidades (default 500, mínimo 50) |

### Añadido

- **`list --json`** (Go y Python): el reporte de `LIST_HIDDEN` como
  `{"pids": [...], "files": [...], "ports": [...]}` — secciones vacías
  como `[]`, y un fichero llamado `pid: 5` sigue siendo un nombre de
  fichero (el contexto de sección decide).
- **`doctor --json`** (Go y Python): el diagnóstico completo como
  documento JSON estable (`device_present`, `version_match`,
  `hooks_installed`, `warnings`, …); los fallos también emiten JSON y
  mantienen el exit code no cero.
- **Suite de tests Python en CI**: el job de Python ejecuta ahora
  `tests/python/test_cli_parsing.py` (unittest stdlib, sin dependencias
  externas) además de compilar y lintear; ruff pasa a cubrir también
  `tests/python/`.
- **ADR 16**: decisión de arquitectura del parser único compartido y
  los esquemas JSON.

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
