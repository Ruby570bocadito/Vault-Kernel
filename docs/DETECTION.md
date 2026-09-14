# Guía de detección — Vault-Kernel (para blue teams)

> Esta guía describe **cómo detectar** un implante LKM de la familia de
> Vault-Kernel (hooking de `sys_call_table` con ABI `pt_regs`, ocultación
> de ficheros/PIDs/puertos, keylogger, backdoor de señal y escalada de
> privilegios). Está pensada para ejercicios de lab autorizados, formación
> defensiva y post-mortem de incidentes donde el uso del implante estaba
> autorizado por escrito.

## 1. Indicadores de compromiso (IOC) específicos

| IOC | Dónde mirar | Notas |
|-----|-------------|-------|
| Nodo de dispositivo `/dev/vault_kernel` | `ls -l /dev/vault_kernel` | El canal de control del implante. Si el módulo está cargado, el nodo existe aunque el módulo esté oculto en `lsmod`. |
| Etiqueta de log `[vault_kernel]` | `dmesg`, `journalctl -k` | El módulo registra verbosamente: carga, hooks instalados, ficheros/PIDs/puertos ocultos, shells lanzadas. Con `dmesg_restrict=1` solo root lo ve — revísalo igualmente. |
| Disco de carga `vault_kernel.ko` | `find / -name 'vault_kernel*'` | El dropper lo deja bajo `/opt/`, `/tmp/`, `/var/tmp/` o rutas con nombre genérico; el servicio de persistencia lo referencia en `ExecStart`. |
| Unidad systemd `dbus-system.service` | `systemctl list-unit-files`, `ls /etc/systemd/system/` | La persistencia imita el nombre del servicio real de D-Bus; `ExecStartPre=/bin/sleep 30` es un patrón raro y sospechoso. |
| Señal 35 con PID imposible | `auditd` (regla sobre `kill(2)`) | El backdoor dispara con `kill(pid, 35)` donde `pid = (puerto << 16) \| hash`. Cualquier `kill` con un pid > 65536 y señal 35 es una firma inequívoca. |
| `bash` hijo de un kthread | `auditd`: `ppid` = `2` (kthreadd) | El reverse shell usa `call_usermodehelper()`: el proceso padre es un hilo del kernel, no un usuario. `execve` de `/bin/bash` con ppid 2 ≈ usermodehelper. |
| Entradas `getdents` que no cuadran | ver §3.3 | Un fichero que `stat` confirma pero `ls` no lista. |

## 2. Comprobaciones rápidas (en vivo, host sospechoso)

```bash
# 1. ¿Nodo de control presente aunque el módulo "no exista"?
ls -l /dev/vault_kernel 2>/dev/null

# 2. ¿Discrepancia lsmod vs /sys/module vs /proc/modules?
lsmod | grep -c vault_kernel                       # 0 en un host limpio
grep -R . /sys/module/ 2>/dev/null | grep -i vault
awk '{print $1}' /proc/modules | grep -i vault

# 3. ¿Logs del kernel con la etiqueta del implante?
dmesg | grep -i "vault_kernel\|sys_call_table\|hooked" | tail -50

# 4. ¿Persistencia sospechosa?
systemctl list-unit-files | grep -iE "dbus-system|vault"

# 5. ¿Ficheros que stat ve pero ls no?
for f in $(find / -xdev -newer /etc/hostname -maxdepth 3 2>/dev/null); do
    ls "$f" >/dev/null 2>&1 || [ -e "$f" ] && ! ls -d "$(dirname $f)"/"$(basename $f)" >/dev/null 2>&1 && echo "OCULTO: $f"
done

# 6. ¿Puertos que ss no ve pero trafico hay?
ss -tulpen > /tmp/ss_now.txt
timeout 60 tcpdump -qnn -i any > /tmp/capture.txt   # compara puertos activos
```

> Estas comprobaciones se pueden esquivar por un rootkit más avanzado
> (hooks en `sys_getdents64`, `sys_read` sobre `/proc/net/*`, etc.), que
> es exactamente lo que hace Vault-Kernel. Por eso el paso 3 (logs) y la
> verificación desde un medio limpio (§4) son las señales más fiables.

## 3. Verificación robusta

### 3.1 Integridad de la syscall table (desde livepatch o memoria)
El implante parchea 7 entradas de `sys_call_table`
(`getdents64`, `getdents`, `openat`, `read`, `kill`, `unlinkat`, `statx`):

```bash
# Con root y kernel < 5.7 (kallsyms_lookup_name exportado):
# compara cada entrada de sys_call_table contra /proc/kallsyms.
# Desviación = hook activo. Herramientas: syscalls-cmp, chkrook, LKRG.
```

- **LKRG** (Linux Kernel Runtime Guard) detecta la mutación de `cred`
  (give-root) y las alteraciones de la syscall table en tiempo real.
- `kernel.kptr_restrict=2` dificulta esta verificación en producción:
  hazla desde una consola administrativa de confianza.

### 3.2 Notifier chain del teclado (keylogger)
El keylogger se registra en la cadena `keyboard_notifier`. Desde un
entorno de forense de memoria (Volatility 2/3 con perfil del kernel),
enumera las cadenas de notificadores y busca callbacks fuera de
`drivers/char/keyboard.c` o del módulo legítimo de tu organización.

### 3.3 Sistemas de ficheros: el hook de `getdents64`
1. Monta el disco **desde otro host** o con `debugfs` (sin pasar por el
   kernel sospechoso) y compara el listado con el obtenido en vivo.
2. En vivo: `find` y `ls` usan `getdents64` (oculto); `stat` de un nombre
   concreto también está hookeado, pero `mount --bind` del directorio y
   la lectura vía `open_by_handle_at` o desde un contenedor con otro
   superblock puede revelar diferencias.
3. Los nombres ocultos viven en memoria del módulo: un dump de memoria
   (LiME) los muestra en texto claro cerca del blob del módulo.

### 3.4 Red: hook de `read()` sobre `/proc/net/tcp*` / `udp*`
- `ss`/`netstat` leen `/proc/net/tcp` → ven la vista filtrada.
- Captura de paquetes (tcpdump, eBPF/TC) muestra las conexiones reales.
- `nft list counters` o `iptables -vnL` acumulan tráfico de puertos que
  "no existen" según `ss`.

### 3.5 Procesos ocultos
- `kill -0 <pid>` devuelve `ESRCH` (el hook de `kill` filtra PIDs ocultos).
- Barre el rango de PIDs con `sched_debug`:
  `grep pid /proc/sched_debug | sort` lista tareas a nivel de scheduler,
  fuera del alcance del hook de `/proc`.

## 4. Forense offline (el estándar de oro)

1. Captura memoria con LiME o `AVML` **antes** de apagar.
2. Apaga por hardware y monta el disco de solo lectura en un host limpio.
3. Con Volatility:
   - `linux_lsmod` y `linux_check_syscall` → hooks de la syscall table.
   - `linux_check_creds` → procesos con credenciales duplicadas/falsificadas
     (el give-root in-place muta `struct cred` compartida).
   - `linux_keyboard_notifiers` → callbacks del keylogger.
   - `linux_hidden_modules` → módulos eliminados de la lista pero mapeados
     (el truco `list_del` de Vault-Kernel deja el `.ko` en memoria).
4. Compara `/boot/System.map-$(uname -r)` con las direcciones observadas.

## 5. Endurecimiento preventivo

| Medida | Efecto contra este implante |
|--------|------------------------------|
| `module.sig_enforce=1` + Secure Boot (claves propias) | El `.ko` sin firma **no carga**; bloquea la vía de entrada entera. |
| `kernel.kexec_load_disabled=1`, `kernel.unprivileged_bpf_disabled=1` | Reduce la superficie para cargadores de segunda etapa. |
| `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1` | El módulo necesita `kallsyms_lookup_name` vía kprobe; sin fugas de direcciones, otros vectores fallan (el kprobe sigue funcionando: no es suficiente solo). |
| LKRG activo | Detecta mutación de `struct cred` (give-root) y corrupción de la tabla de syscalls. |
| `kernel.kprobes_optimization` / compilar sin `CONFIG_KPROBES` en hosts críticos | El fallback de localización de `sys_call_table` usa un kprobe: sin KPROBES el módulo no encuentra la tabla y **se niega a cargar** (`-ENODEV`). |
| auditd: `-a always,exit -F arch=b64 -S kill -S init_module -S finit_module` | Firma la señal 35 con pid enorme y toda carga de módulos. |
| SELinux/AppArmor con confinement de kmod, systemd de persistencia monitorizado | Bloquea el dropper y la unidad `dbus-system.service`. |

## 6. Respuesta a incidentes

1. **No confíes en el propio host** para contener: el atacante con
   `give-root` es kernel-root. Aísla en red a nivel de switch/hipervisor.
2. Captura memoria y discos (§4) antes de desmontar.
3. No hagas `rmmod` con el módulo oculto (`auto_hide=1`): el cleanup de
   stealth re-inserta el módulo en la lista, pero si el atacante
   corrompió los punteros guardados el `rmmod` puede paniquear. La
   captura de memoria es la prioridad, no la desinstalación limpia.
4. Rotación completa de credenciales del host (el keylogger pudo capturar
   cualquier tecleo previo, incluidas contraseñas de root).
5. Reconstruye el host desde imagen conocida buena; el implante es un
   LKM en memoria + fichero en disco, sin firmware persistence, pero el
   dropper pudo ejecutar acciones adicionales no documentadas aquí.
