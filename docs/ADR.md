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

## 16. v3.6 — Salida máquina JSON de los CLIs con un único parser compartido

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** El reporte de `GET_STATS` emite VARIOS pares `clave=valor`
por línea (`module=vault_kernel version=3.5`) y los CLIs lo parseaban
por líneas partiéndolo en el primer `=`: cada par después del primero se
tragaba. Efecto: `stats --json` (v3.5) perdía `version`,
`hooks_planned`, `hidden_pids` y `hidden_ports`, y el check de versión
de `doctor` (v3.4) nunca podía dispararse. Reproducido con el código
real de ambos clientes: 6 claves de 10.

**Decisión.** Un único parser por tokens como fuente de verdad en cada
cliente — `ParseStatsReport`/`ParseHiddenList` en
`client/go/internal/vaultkernel` y `parse_stats_report`/
`parse_hidden_list` en el CLI Python — que divide por espacios en
blanco y después cada token en su primer `=`. El formato de texto del
kernel NO cambia (es estable, legible y lo consumen los tests de VM);
la traducción a JSON (`stats --json`, `list --json`, `doctor --json`)
es responsabilidad exclusiva de los clientes. Los parsers son código de
producción y por tanto viven en el repo con tests que corren en CI
(suite Go + unittest stdlib Python), a diferencia de los arneses de
verificación, que siguen fuera.

**Consecuencias.** Los tres comandos de lectura emiten JSON estable
(esquema de `doctor` documentado en el ADR y testado; `list --json`
renderiza secciones vacías como `[]`); un desajuste futuro de formato
entre módulo y clientes lo detecta la CI antes de que llegue a la VM.
El contexto de sección decide en `ParseHiddenList` cómo interpretar
cada entrada, así que un fichero llamado literalmente `pid: 5` sigue
siendo un nombre de fichero.

## 17. v3.7 — Salida máquina versionada (campo `schema`) y comando `watch`

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** Desde v3.6 los tres comandos de lectura (`stats --json`,
`list --json`, `doctor --json`) emiten JSON estable, pero el documento
no declara SU propia versión: un script de lab que valide forma no
puede distinguir "el módulo cambió" de "el cliente cambió de esquema".
Además la auditoría de la ronda 4 encontró que las rutas de fallo de
`doctor --json` no eran idénticas entre clientes hermanos: el CLI Go
declaraba `device_open`/`stats_responds` como `bool` con `omitempty`,
así que la clave DESAPARECÍA del JSON exactamente cuando la
comprobación fallaba, mientras el CLI Python la emitía como `false`.

**Decisión.** (1) Envelope versionado: los tres comandos JSON de AMBOS
clientes añaden el campo entero `"schema"` (valor actual `1`, constante
compartida `jsonSchemaVersion`/`JSON_SCHEMA_VERSION`); es aditivo y
compatible, y se incrementará solo cuando un campo cambie de forma o de
significado. El schema vive en la capa de comando (no en los parsers):
el kernel no emite schema, es propiedad del formato de salida del
cliente. (2) Paridad por punteros: en Go, `device_open` y
`stats_responds` pasan a `*bool` con asignación explícita en éxito y
fallo (la misma semántica que ya tenían `keylog_responds`/
`list_responds`): la clave aparece si la comprobación llegó a ejecutar
y desaparece solo si no llegó a ejecutarse — exactamente el contrato
testado del cliente Python. (3) Comando `watch`: vista en vivo de stats
+ listado con refresco configurable (`--interval MS`, default 1000,
suelo 50, como `keylog --follow`); el render es una función PURA
(`RenderWatchPanel` en el paquete interno Go, `format_watch_panel` a
nivel de módulo en Python) testeada en CI, y el bucle solo posee el
clear ANSI, la cadencia y la restauración del cursor. Sin dependencias
externas (sin tview/ncurses), coherente con la política cero-deps.
(4) Los argumentos de intervalo se parsean con un validador dedicado
(`_ms_arg` en Python): enteros de texto, sin negativos; los no finitos
(`nan`/`inf`) que v3.6 dejaba llegar a `time.sleep()` se rechazan ahora
con error de uso claro.

**Consecuencias.** Un consumidor de lab puede fijar `jq -e '.schema ==
1'` y detectar cualquier cambio futuro de forma en vez de fallar en
silencio; los dos clientes emiten el MISMO documento `doctor --json` en
los tres caminos (éxito, fallo de comprobación, fallo de dispositivo),
verificado por tests en ambos lados; `watch` reutiliza los parsers
compartidos de v3.6 sin tocar el módulo, y su panel es un contrato
fijado por tests espejo (Go y Python) para que las paridades futuras no
se rompan en silencio.

## 18. v3.8 — Paridad de superficie de comandos, `keylog --timestamps` y bits de ejecución

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** Los dos CLIs (Go y Python) son hermanos con paridad de
comportamiento como objetivo, pero la ronda 5 encontró tres desajustes
reales: (1) `give-root` en Go descartaba el error de `strconv.Atoi`
(`pid, _`), de modo que un PID no numérico se convertía en pid=0 y
escalaba SELF en silencio — el CLI Python lo rechaza como error de uso
(`argparse type=int`); un typo ejecutaba una operación distinta a la
pedida, y en un plano de control eso es un bug aunque el camino
resultante sea "válido". (2) El CLI Python no tenía comando `version`
(el Go lo tiene desde v3.6). (3) La gramática de `keylog` en Go
aceptaba argumentos desconocidos en silencio en el camino one-shot
(`keylog 500` sin `--follow` ignoraba el intervalo), mientras Python
(argparse) los rechaza. A esto se añade una demanda de producto del
lab: correlacionar temporalmente capturas del keylogger, que hoy se
imprimen sin ninguna referencia temporal.

**Decisión.** (1) `give-root` Go extrae el parsing a `parseGiveRootPID()`
— función pura testeable: sin argumento (o pid<=0) sigue siendo "self"
por contrato documentado del módulo, argumento no numérico y argumentos
extra son error de uso; el contrato del kernel NO cambia. (2) El CLI
Python añade `version` con `format_version_line()`, que replica el
texto exacto de `printVersion()` de Go (client version, magic 0xC0,
señal 35). (3) `keylog` Go extrae su gramática a `parseKeylogArgs()` —
estricta: `--follow` y `--timestamps` en cualquier orden, intervalo
posicional solo tras `--follow` (suelo 50 ms), cualquier otro argumento
es error; `--timestamps` sin `--follow` es error en AMBOS clientes.
(4) La marca de tiempo de `keylog --follow --timestamps` es la del
SONDEO que mostró el contenido, no de la pulsación: el buffer del
módulo no lleva tiempo por tecla y falsear una precisión que no existe
sería peor que una cota honesta — se documenta en la ayuda y en
SCHEMAS/README. Sin `--timestamps`, la salida es byte-idéntica a v3.7.
El formateo vive en funciones puras espejo (`formatKeylogEvent` /
`format_keylog_event`) con tests en ambos clientes. (5) Higiene de
repo: todo fichero con shebang se versiona con bit de ejecución
(política: un fichero ejecutable por shebang debe poder ejecutarse
directo tras el clone), y `.gitignore` declara explícitamente
`.ruff_cache/` aunque el caché se auto-excluya.

**Consecuencias.** La paridad de superficie de comandos Go/Python
queda completa para todos los comandos de lectura y de argumentos
simples; el contrato de los documentos JSON de ambos clientes está
documentado en `docs/SCHEMAS.md` (junto al campo `schema` de ADR 17);
las gramáticas de argumentos son ahora funciones puras con tests, de
modo que el próximo flag hereda el patrón en vez de crecer dentro del
`switch`; y la auditoría de la ronda fija el método definitivo de
verificación de caracteres: `od -c` (el canal de render del agente se
come secuencias ANSI incluso dentro de salidas `repr()` — los conteos
de corchetes de la ronda 4 detectan desequilibrios, no caracteres
ausentes).

## 19. v3.9 — `capture` (evidencia), `keylog --output`, autocompletado bash y cierre sistémico de las gramáticas

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** Tres demandas convergen en la ronda 6. (1) Un lab de red
team que documenta hallazgos necesita citar el estado del implante en
UN artefacto: hoy encadena `stats --json`, `list --json` y una lectura
de `keylog` a mano, sin timestamp compartido ni garantía de que las
tres lecturas describen el mismo instante. (2) Las capturas del
keylogger se pierden al cerrar el terminal: el stream solo se imprime
y el operador lo redirige ad-hoc (perdiendo las marcas de tiempo o el
diff de eventos según cómo lo haga). (3) La auditoría de la ronda
construyó la primera matriz comando×cliente de gramáticas y halló un
patrón SISTÉMICO, no puntual: el dispatcher Go validaba "argumentos
suficientes" pero nunca rechazaba el exceso — 15 de 20 cases ignoraban
argumentos extra en silencio (`hide-file a b` ocultaba "a", `watch
--interval 500 extra` ignoraba "extra", `list extra` listaba igual) —
mientras el CLI Python (argparse) los rechaza todos; además `shell` no
validaba `ip:port` (Go: "contiene :", Python: nada) y `hide-pid`
aceptaba pid <= 0 en ambos (el módulo añade cualquier int a la lista:
"pid: -5"). Por último, el cuarto documento JSON que `capture` añade
dispara la condición que el backlog de v3.8 dejó escrita: reestructurar
SCHEMAS.md por comando.

**Decisión.** (1) `capture` es un comando nuevo en AMBOS clientes:
builders puros espejo (`buildCaptureReport` / `build_capture_bundle`)
que ensamblan el envelope contractual schema/captured_at/
client_version/module_in_sysfs/stats/hidden/keylog; `stats` reutiliza
la MISMA conversión numérica de `stats --json` (extraída a `statsMap`
en Go para que ambas salidas la compartan) y `hidden` la forma de
`list --json`; `captured_at` es UTC RFC3339 del SNAPSHOT (leído tras
los buffers: cota superior honesta, no tiempo por evento); con `--out
FILE` el fichero se crea 0600 porque un bundle puede contener
pulsaciones — la misma política que aplica `keylog --output`. (2)
`keylog --output FILE` escribe cada evento tal y como se imprime
(transcripción fiel, marcas incluidas si `--timestamps`) en un fichero
apéndice con flush+fsync por evento; la apertura es PEREZOSA (con el
primer registro): un buffer vacío no crea fichero, semántica idéntica
en ambos clientes. La gramática extiende `parseKeylogArgs`/argparse:
operand obligatorio, un solo `--output`, cualquier posición.
(3) Autocompletado bash autocontenido (sin paquete bash-completion)
para los DOS binarios, con flags por subcomando y fallback a ficheros
en hide-file/unhide-file; se instala con `source` o copiando a
/etc/bash_completion.d/. Su test funcional (`tests/test_completions.sh`,
11 checks) maneja COMP_WORDS/COMP_CWORD directamente y corre en CI
(nuevo job: 8 jobs). (4) Cierre de la política de gramáticas: TODOS
los parsers son funciones puras testeadas (`parseWatchArgs`,
`parseShellTarget`, `parsePIDArg`, `parseCaptureArgs`,
`parseKeylogArgs`, `parseGiveRootPID`) y TODO case del dispatcher
rechaza argumentos extra — la regla del repo pasa a ser "los errores
de argumentos nunca se descartan ni se ignoran" (extensión de la
recomendación 1 de la ronda 5); `shell` valida host no vacío + puerto
1-65535 con split por el ÚLTIMO `:` (IPv6 literal queda fuera por
contrato del módulo, que parte en el primero), `hide-pid`/`unhide-pid`
exigen pid >= 1 en ambos clientes (el contrato kernel no cambia). (5)
SCHEMAS.md se divide en docs/schemas/{stats,list,doctor,capture}.md
con SCHEMAS.md como índice.

**Consecuencias.** Un operador documenta con `capture --out
evidencia.json` y cita un único fichero con permisos 0600; los capturas
sobreviven al terminal y son transcriptibles byte a byte; el tabula
completa comandos y flags en los dos clientes sin dependencias; los
caminos de error de argumentos son IDÉNTICOS entre clientes y están
pinados por tests (la clase de bug "silencioso" queda cerrada
estructuralmente, no caso a caso); y el contrato JSON vive en cuatro
páginas por comando que crean sin fricción cuando el módulo gane su
quinto documento.

## 20. v3.10 — `watch --once` con anotación de cambios, parada limpia por señales y el quinto documento JSON (`status --json`)

**Fecha:** 2026-09-15 · **Estado:** Aceptado e implementado

**Contexto.** Cuatro demandas convergen en la ronda 7. (1) El backlog
de v3.8/v3.9 dejaron escrito el deseo de un `watch` diferencial; un
operador necesita además SNAPSHOTAR el panel para scripts, CI y
reportes — hoy el bucle limpia la pantalla con ANSI y no termina nunca,
imposible de capturar. (2) Los bucles largos solo terminan limpios por
Ctrl-C: `systemd stop` o `pkill -TERM` matan el CLI a mitad de
escritura del sink de `keylog --output` (flush por evento mitiga, la
parada ordenada es la barrera correcta) y el cursor de `watch` puede
quedar oculto; además la despedida `[*] Follow stopped` existía solo en
Python (Go salía en silencio — paridad rota). (3) La auditoría de la
ronda extendió la matriz comando×cliente a los VALORES de flag: Go
aceptaba `keylog --output --follow` (crearía un fichero llamado
`--follow`) y `capture --out --json`; argparse los rechaza. Y la
comprobación "¿está plantado?" es la única superficie de estado sin
documento JSON, además de la única que puede funcionar sin root. (4)
Tres errores documentales medidos contra el código (conteos de suite
intermedios, "seven jobs", epílogo del `--help` Python) y un dead code
verificado (`case "version"` del dispatcher).

**Decisión.** (1) `watch --once` (AMBOS clientes): un fotograma a
stdout SIN ANSI, sin bucle, sin manejo de cursor; gramática pura
extendida con tests espejo. El bucle en vivo gana anotación de cambios:
`RenderWatchPanelDiff`/`format_watch_panel(prev_stats=...)` marcan
` (was X)` en los stats que variaron y ` (new)` en las claves nuevas;
prev nil/None (primer fotograma, `--once`) reproduce el panel clásico
byte a byte — la función anterior queda como wrapper. SOLO se anota la
sección de stats: los contadores del módulo (hidden_files/pids/ports)
ya reflejan las variaciones de las listas; diferenciar las listas
completas añadiría ruido sin valor de lab. (2) Señales: SIGTERM se
enruta por el MISMO camino de parada limpia que Ctrl-C en los cuatro
bucles largos (Go: `signal.Notify(os.Interrupt, syscall.SIGTERM)` y
`select` en el sleep; Python: handler que lanza KeyboardInterrupt, así
los finally existentes hacen el trabajo); la despedida
`\n[*] Follow stopped` se unifica en ambos clientes. El mensaje de
`watch` no cambia. (3) `status --json` es el QUINTO documento del
contrato: envelope `schema/device_present/module_in_sysfs` siempre
presentes y `modinfo` (filename/version/author/description en orden
contractual) OMITIDO — nunca null — cuando el dispositivo no existe o
`modinfo` no produce claves del contrato; política best-effort
documentada en `docs/schemas/status.md` (modinfo lee el FICHERO del
módulo, no la lista del kernel: un módulo lsmod-oculto puede tener
sección completa si está instalado en /lib/modules). El parser de
modinfo es EXACTO por claves (`parse_modinfo`/`parseModinfo`, puros y
testeados) — el substring-matching que imprimía `srcversion` se
elimina, y el `status` Go gana las líneas modinfo del texto (paridad
con Python). El CLI Python recibe además el par `--version`/`-v` (Go lo
tiene desde v3.6). (4) Regla global de VALORES de flag: los parsers con
operand (`parseKeylogArgs`/`parseCaptureArgs` — ROL 4 de esta ronda)
rechazan valores que empiezan por `-` con mensaje que enseña el escape
`./-foo`; los errores documentales se corrigen (README, epílogo del
CLI) y el dead code se elimina.

**Consecuencias.** El operador captura el panel con `watch --once >
frame.txt` para scripts y ve QUÉ cambió en cada refresco del bucle sin
diff a ojo; los streams de `keylog --output` sobreviven a `systemd
stop` con el fichero íntegro; los scripts de lab hacen `status --json |
jq -e '.device_present'` sin root; el contrato JSON crece a cinco
páginas por comando sin fricción (la convención de la ronda 6 se
cumple); y los dos clientes documentan y validan la MISMA superficie —
incluidos los valores de flag, cerrando la última clase de error
silencioso conocida del dispatcher.
