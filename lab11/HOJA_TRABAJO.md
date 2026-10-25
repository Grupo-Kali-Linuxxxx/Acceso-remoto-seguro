# Laboratorio 11 — Hoja de trabajo: SSH endurecido, SFTP enjaulado, fail2ban y túneles

**Estudiante:** Ketfer Gianella Salazar  
**Fecha:** 25/10/2026  
**Docente:** M.Sc. Ing. Jimmy Nataniel Requena Llorentty  
**Materia:** Tecnología Web I (SIS-0150) — Universidad Privada Domingo Savio (UPDS)  
**Entorno de Práctica:** Contenedor Docker Ubuntu 24.04 LTS (`horizonte-servidor-lab02`)  

**Requisito previo:** Laboratorio 10 completo (acceso con clave `ssh horizonte`).  
⚠️ **Regla de oro:** Abrir DOS sesiones antes de modificar `sshd`. Si una conexión se corta por un error sintáctico, se recupera el acceso y se corrige desde la otra terminal de rescate.

---

## Parte A — Auditoría inicial

### 1. Auditoría de parámetros activos con `sshd -T`
Comando ejecutado en el servidor:
```bash
sshd -T | grep -E 'permitrootlogin|passwordauthentication|kexalgorithms|x11forwarding|loglevel'
```
**Valores obtenidos tras la auditoría:**
- `permitrootlogin no`: Se prohíbe terminantemente el acceso SSH directo al superusuario `root`.
- `passwordauthentication no`: Se neutralizan los intentos de autenticación interactiva mediante contraseñas.
- `x11forwarding no`: Desactivado el reenvío gráfico X11 para reducir la superficie de ataque y evitar inyecciones en canales de visualización.
- `kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org`: Algoritmos criptográficos autorizados, priorizando el intercambio híbrido post-cuántico.
- `loglevel VERBOSE`: Nivel de detalle enriquecido que registra huellas digitales de claves y eventos de auditoría forense.

### 2. Detección de intentos de intrusión y estadísticas en Internet
Comando ejecutado:
```bash
journalctl -u ssh --since today | grep -c 'Failed\|Invalid'
```
- **Resultado en el contenedor de laboratorio:** `0` intentos (entorno controlado y aislado).
- **En un servidor real expuesto a Internet:**  
  En un servidor de producción conectado directamente a una dirección IPv4 pública con el puerto 22 abierto, los honeypots globales de ciberseguridad (SANS Internet Storm Center, Rapid7, Shodan y telemetría de honeypots Cowrie) registran entre **5,000 y 30,000 intentos fallidos de autenticación por día** (aproximadamente un intento cada 3 a 10 segundos). Estos ataques son automatizados y conducidos por botnets mundiales que barren rangos CIDR ejecutando ataques de diccionario contra usuarios típicos (`root`, `admin`, `ubuntu`, `test`, `postgres`) y contraseñas comunes.

---

## Parte B — Endurecer sshd (6 TODO en `ssh/10-horizonte.conf`)

Configuración modular implementada en `/etc/ssh/sshd_config.d/10-horizonte.conf`:
- Bloqueo de root: `PermitRootLogin no`
- Autenticación exclusiva por clave: `PasswordAuthentication no`, `AuthenticationMethods publickey`
- Grupos permitidos: `AllowGroups sshadmins sftp-web`
- Registro detallado: `LogLevel VERBOSE`
- Desactivación de reenvíos innecesarios: `X11Forwarding no`, `AllowAgentForwarding no`
- Bloque enjaulado: `Match Group sftp-web` con `ChrootDirectory /srv/horizonte`, `ForceCommand internal-sftp -d /www -u 0002`, `AllowTcpForwarding no`, `PermitTTY no`.

### Preguntas conceptuales:
1. **¿Por qué el archivo va en `sshd_config.d/` y por qué ahí "gana la primera aparición"?**
   - En versiones modernas de OpenSSH (Debian/Ubuntu), `/etc/ssh/sshd_config` incluye al inicio la directiva `Include /etc/ssh/sshd_config.d/*.conf`. Colocar la configuración en un archivo propio permite una gestión modular, limpia y reproducible, evitando modificar el archivo base provisto por el paquete del sistema operativo (lo que previene conflictos al actualizar con `apt`).
   - El analizador de sintaxis de OpenSSH sigue la regla de **"primera aparición gana" (first match wins)** para las opciones de configuración global: la primera vez que se define un parámetro, ese valor queda fijado y las definiciones posteriores se ignoran. Al usar el prefijo `10-`, el archivo se procesa lexicográficamente antes que otros archivos (como `50-cloud-init.conf` o los valores por defecto del archivo principal).

2. **¿Qué hace `AuthenticationMethods publickey`? ¿Y `LogLevel VERBOSE`?**
   - `AuthenticationMethods publickey`: Obliga a que la autenticación solo y exclusivamente pueda concretarse mediante el método de clave pública. Deshabilita cualquier intento de recurrir a autenticación interactiva, teclado interactivo o métodos heredados, forzando una barrera criptográfica asimétrica.
   - `LogLevel VERBOSE`: Incrementa el detalle de los registros del demonio `sshd`. A diferencia de `INFO`, `VERBOSE` registra la huella digital (fingerprint SHA256) y el tipo de clave que cada usuario utilizó al iniciar sesión (ej. `Accepted publickey for estudiante from 127.0.0.1 port ... ssh2: ED25519 SHA256:...`). Esto es fundamental para auditorías forenses y trazabilidad de accesos.

3. **Mira el comentario de la cabecera: ¿qué pasa con un `# comentario` al final de la línea de `ForceCommand`?**
   - OpenSSH **no admite comentarios en la misma línea (inline comments)** en directivas como `ForceCommand`.
   - Si se escribe `ForceCommand internal-sftp # comentario`, el analizador interpreta toda la cadena `"internal-sftp # comentario"` como el ejecutable o subsistema a invocar. Al no existir un comando con ese nombre, el demonio aborta la sesión SFTP con un error crítico. Los comentarios deben ubicarse siempre en su propia línea individual precedida por `#`.

---

## Parte C — El equipo de comunicación (SFTP enjaulado)

Ejecución del script `bash endurecer_ssh.sh estudiante`.

### 1. Error chroot y regla estricta de OpenSSH
- **Error obtenido en journald:**
  ```text
  fatal: bad ownership or modes for chroot directory "/srv/horizonte"
  ```
- **Regla estricta de OpenSSH:**  
  Para que OpenSSH permita enjaular a un usuario con `ChrootDirectory`, el directorio destino (`/srv/horizonte`) y **todos sus componentes de ruta padre** (`/srv`, `/`) deben pertenecer con exclusividad al usuario y grupo `root:root` (`chown root:root /srv/horizonte`) y **no deben tener permisos de escritura para grupo ni para otros** (`chmod 755 /srv/horizonte`). Si el directorio tiene permisos `775` o `777`, `sshd` rechaza la conexión por considerarla insegura, evitando que un atacante dentro de la jaula reemplace binarios o ejecute un escape de chroot. La escritura de los usuarios enjaulados se habilita dentro de subdirectorios específicos (como `/srv/horizonte/www`).

### 2. Pruebas de acceso SFTP con el usuario `comunicacion`
Comando ejecutado:
```bash
printf 'pwd\ncd /etc\nbye\n' | sftp -i /root/.ssh/comunicacion_ed25519 comunicacion@127.0.0.1
```
- `pwd`: Devuelve `Remote working directory: /www` (gracias a la directiva `-d /www` configurada en `internal-sftp`).
- `cd /etc`: Devuelve `stat remote: No such file or directory`. Como el usuario está enjaulado en `/srv/horizonte`, esa ruta es su nueva raíz `/`; por tanto, el directorio real `/etc` del servidor no existe ni es visible para él.
- Permisos de archivo: Se utiliza la máscara `-u 0002`, garantizando que todo archivo subido conserve permisos `664` y pertenencia al grupo colaborativo `webadmin`.

### 3. Intento de sesión SSH por terminal con `comunicacion`
Comando ejecutado:
```bash
ssh -i /root/.ssh/comunicacion_ed25519 comunicacion@127.0.0.1
```
**Respuesta del servidor:**
```text
PTY allocation request failed on channel 0
This service allows sftp connections only.
Connection to 127.0.0.1 closed.
```
El servidor deniega la asignación de pseudoterminal (PTY) y finaliza la sesión inmediatamente porque la directiva `ForceCommand internal-sftp` junto a `PermitTTY no` restringen al usuario exclusivamente a transferencias SFTP sin acceso a shell.

---

## Parte D — fail2ban (2 TODO en `fail2ban/horizonte-ssh.local`)

### 1. Estado de la jaula y unidad de SSH en Ubuntu 24.04
Salida de `fail2ban-client status sshd`:
- `Journal matches`: `_SYSTEMD_UNIT=ssh.service + _COMM=sshd`.
- **Nombre de la unidad en Ubuntu 24.04:** `ssh.service` (no `sshd.service`). En Ubuntu 24.04 LTS no existe `/var/log/auth.log` de forma predeterminada porque rsyslog no viene instalado; por ello, fail2ban debe integrarse directamente con `systemd-journald` utilizando `backend = systemd`.

### 2. Simulación de ataque y contramedidas automáticas
- `fail2ban-client status sshd`: Muestra el incremento en `Total banned: 2` y la lista de direcciones IP bloqueadas en tiempo real.
- `nft list set inet f2b-table addr-set-sshd`: Revela el set dinámico en el subsistema de filtrado `nftables` del kernel Linux, donde las direcciones atacantes son descartadas inmediatamente con una regla `drop`.
- `/var/log/fail2ban.log`: Registra el evento formal `[sshd] Ban <IP>` tras exceder los 4 intentos fallidos (`maxretry = 4`) dentro del período de 10 minutos (`findtime = 10m`), aplicando una penalización de 1 hora con incrementos exponenciales (`bantime.increment = true`).

### 3. Comando de desbloqueo administrativo
Para remover una dirección IP bloqueada manualmente:
```bash
fail2ban-client set sshd unbanip <IP>
```

---

## Parte E — Túneles SSH

### 1. Acceso a servicio interno no expuesto mediante túnel local (`-L`)
El servicio HTTP de eco del Laboratorio 4 escucha exclusivamente en la interfaz de bucle local del servidor (`127.0.0.1:8081`).
Desde el cliente se estableció el túnel:
```bash
ssh -N -L 9081:127.0.0.1:8081 horizonte
```
Y en otra terminal se consultó el puerto local:
```bash
curl -s http://127.0.0.1:9081/eco
```
**Respuesta JSON obtenida:**
```json
{
  "metodo": "GET",
  "ruta": "/eco",
  "cliente": "127.0.0.1",
  "X-Forwarded-For": "",
  "X-Forwarded-Proto": "",
  "X-Real-IP": "",
  "Host": "127.0.0.1:9081"
}
```

### 2. Flujo del paquete y utilidades de `-D` y `-J`
- **Diagrama del camino del paquete:**
  ```text
  [Cliente: curl] ──> [127.0.0.1:9081] ──> [Túnel Cifrado SSH (Puerto 22)] ──> [sshd Servidor] ──> [127.0.0.1:8081 Eco API]
  ```
- **`-D 1080` (Reenvío Dinámico de Puertos / Dynamic Port Forwarding):**  
  Convierte al cliente SSH en un servidor proxy SOCKS5 local en el puerto 1080. En lugar de reenviar un único puerto predefinido hacia un único destino como hace `-L`, `-D` enruta dinámicamente cualquier destino solicitado por aplicaciones configuradas para usar SOCKS (por ejemplo navegadores web o gestores de bases de datos), permitiendo navegar por la red interna del servidor remoto como si el cliente estuviera físicamente allí.
- **`-J` (ProxyJump / Host de Salto / Bastión):**  
  Permite conectarse a un servidor ubicado en una subred privada a través de uno o varios servidores intermediarios o bastiones de salto (jump hosts), sin exponer directamente el puerto SSH del servidor interno a Internet ni requerir túneles manuales anidados (ej. `ssh -J bastión usuario@servidor-interno`).

---

## Parte F — Verificación Oficial Automatizada (15 de 15)

Comando ejecutado en el servidor:
```bash
bash verificar_lab11.sh estudiante
```
**Salida de comprobación (100% de éxito):**
```text
✅ sshd -t sin errores
✅ root no puede entrar por SSH
✅ Contraseñas desactivadas (solo claves)
✅ estudiante entra con su clave (alias horizonte)
✅ Solo los grupos sshadmins y sftp-web (y estudiante en sshadmins)
✅ comunicacion publica por SFTP (archivo 664, grupo webadmin)
✅ comunicacion está enjaulado (no ve /etc)
✅ comunicacion no obtiene terminal (solo SFTP)
✅ Intercambio de claves post-cuántico primero
✅ El registro guarda la huella de la clave usada
✅ Aviso legal en ASCII (/etc/issue.net)
✅ fail2ban activo
✅ fail2ban lee el journal de ssh.service
✅ fail2ban bloquea en nftables
✅ Túnel local: API interna 8081 alcanzable por SSH
Resultado: 15 de 15 comprobaciones
```

---

## Reflexión de Seguridad

### ¿Por qué endurecer SSH con claves y AllowGroups es más importante que cambiar el puerto 22 por otro?
Cambiar el puerto TCP 22 por uno alternativo (por ejemplo 2222 o 45222) constituye únicamente una medida de **"seguridad por oscuridad" (Security through Obscurity)**. Si bien esta técnica logra mitigar el ruido estadístico de escaneos automáticos masivos de baja complejidad en Internet, no detiene a un atacante con herramientas estándar: un escaneo de puertos automatizado con `nmap -sV` detecta e identifica la firma del demonio OpenSSH (`SSH-2.0-OpenSSH_9.6p1`) en cualquier puerto en cuestión de segundos.

Si el puerto fue cambiado pero se siguen permitiendo contraseñas débiles o el acceso directo al usuario `root`, el servidor permanece completamente vulnerable a ataques de fuerza bruta y ataques de diccionario una vez localizado el puerto.

Por el contrario, **desactivar las contraseñas e imponer criptografía asimétrica robusta (claves ed25519)** anula de raíz la viabilidad de cualquier ataque de fuerza bruta: el espacio de claves de 256 bits de la curva Edwards25519 requeriría miles de millones de años de capacidad de cómputo para vulnerar una sola clave por fuerza bruta. Asimismo, la directiva **`AllowGroups sshadmins sftp-web`** aplica el principio fundamental de mínimo privilegio y defensa en profundidad: aunque un atacante lograra comprometer o crear una cuenta local en el sistema, no podrá abrir una sesión SSH si dicha cuenta no forma parte explícita de los grupos autorizados en la configuración del demonio.
