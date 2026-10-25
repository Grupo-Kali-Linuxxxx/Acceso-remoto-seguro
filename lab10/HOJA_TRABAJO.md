# Laboratorio 10 — Hoja de trabajo: TELNET vs SSH, "la prueba del espía"

**Estudiante:** Ketfer Gianella Salazar  
**Fecha:** 25 de Octubre de 2026  
**Docente:** M.Sc. Ing. Jimmy Nataniel Requena Llorentty  
**Asignatura:** Tecnología Web I (SIS-0150) — Universidad Privada Domingo Savio  
**Entorno de Laboratorio:** Docker en Windows 11 (`horizonte-servidor-lab02`)  
**Usuario Administrador:** `estudiante` (creado y configurado en el Lab 2, grupo `webadmin`)  
**Usuaria de Prueba:** `secretaria` / `Circular2026`  

---

## Parte A — La prueba del espía

### 1. ¿En qué estado venía TELNET en Ubuntu 24.04? (mira `/etc/inetd.conf`)
En Ubuntu 24.04 LTS (Noble Numbat), TELNET viene **totalmente desactivado por defecto**. Al revisar el archivo `/etc/inetd.conf`, la línea del servicio se encuentra comentada con el prefijo `#<off># telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd`. Esto responde a una política moderna de endurecimiento del sistema (*hardening*), ya que los sistemas operativos de grado servidor deshabilitan protocolos no cifrados para prevenir accesos inseguros.

### 2. Tabla comparativa: TELNET (puerto 23) vs SSH (puerto 22)

| Pregunta de Evaluación | TELNET (puerto 23) | SSH (puerto 22) |
|---|---|---|
| **¿Se lee el usuario?** | **Sí, `secretaria`** (se transmite en texto plano carácter por carácter). | **No** (el canal se cifra antes del proceso de autenticación de usuario). |
| **¿Se lee la contraseña?** | **Sí, `Circular2026`** (capturada íntegramente por cualquier analizador de paquetes). | **No** (se autentica dentro de un túnel seguro con ChaCha20-Poly1305 o clave pública). |
| **¿Se lee lo que se escribió en la sesión?** | **Sí, `notas-confidenciales-5to-B`** (comandos y respuestas visibles en texto plano). | **No** (todo el flujo de datos viaja cifrado con alta entropía). |
| **¿Qué se ve en claro en la captura?** | **Absolutamente todo**: credenciales, prompts del sistema (`login:`, `Password:`), comandos ejecutados y respuestas del shell. | **Solo metadatos de negociación inicial**: la versión del protocolo (`SSH-2.0-OpenSSH_9.6p1`), IPs y puertos de transporte. |

### 3. Flujo TCP en Wireshark (`resultados/telnet.pcap`)
Al abrir la captura `telnet.pcap` e inspeccionar el flujo TCP (*Follow TCP Stream*), la conversación completa queda expuesta en texto legible sin requerir ninguna clave de descifrado: el texto en rojo muestra las pulsaciones enviadas por el cliente (`secretaria` y `Circular2026`), mientras que el texto en azul muestra las respuestas del daemon del servidor. En contraste, en `ssh.pcap` todo el contenido de la capa de aplicación aparece como una secuencia binaria ininteligible.

### 4. ¿Por qué existe todavía TELNET en algunos equipos (routers, impresoras)?
1. **Limitaciones de hardware en equipos legados o embebidos:** Switches antiguos, impresoras industriales y terminales de punto de venta (POS) cuentan con microcontroladores con memoria RAM y capacidad de cómputo tan reducidas que no pueden sostener la carga de cómputo de los algoritmos criptográficos asimétricos y simétricos de SSH.
2. **Deuda técnica y redes aisladas:** Equipos de red antiguos que operan en redes de control industrial (OT/SCADA) o consolas serie de gestión fuera de banda donde se asumió falsamente que la red física ofrecía suficiente protección perimetral.
3. **Herramienta diagnóstica universal:** El comando `telnet <host> <puerto>` se sigue empleando como una utilidad simple para diagnosticar rápidamente la apertura y respuesta de puertos TCP arbitrarios (ej. SMTP 25, HTTP 80).

---

## Parte B — ¿Con quién estoy hablando? (claves de host)

### 1. ¿Qué dice el comentario de la clave y qué problema hay en imágenes clonadas?
- **Comentario original:** Al ejecutar `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` en la imagen original, el comentario mostraba `root@buildkitsandbox` (o `@localhost`).
- **Problema de seguridad:** Una clave de host es la "cédula de identidad criptográfica" del servidor. Si múltiples máquinas virtuales o contenedores clonados comparten la **misma clave privada de host**, cualquier estudiante o atacante que posea una copia puede:
  - Montar un ataque de intermediario (**Man-in-the-Middle / MitM**) interceptando las conexiones de los demás sin que el cliente detecte discrepancias en `known_hosts`.
  - Suplantar completamente al servidor del colegio y robar las credenciales de los administradores.

### 2. Regeneración de claves de host (TODO 1 de `preparar_ssh.sh`)
Se implementó la eliminación de las claves heredadas (`rm -f /etc/ssh/ssh_host_*`) y la regeneración de claves maestras únicas mediante `ssh-keygen -A`. La nueva huella digital generada es única para el servidor de la institución:
`256 SHA256:FodAJ6yz7TTA0QmnKAAAxGbSHmsxw+OtlTdC8msgaD8 root@srv-horizonte (ED25519)`

### 3. Algoritmo de intercambio de claves (KEX) negociado
- **Algoritmo negociado:** `sntrup761x25519-sha512@openssh.com`
- **¿Qué significa "sntrup761x25519"?:** Es un mecanismo de intercambio de claves **híbrido post-cuántico**. Combina la velocidad y solidez del algoritmo clásico de curvas elípticas **X25519** con el algoritmo de criptografía basada en retículos **Streamlined NTRU Prime (sntrup761)**. Este último está diseñado para ser matemáticamente inviolable frente a computadoras cuánticas ejecutando el algoritmo de Shor, neutralizando la amenaza de atacantes que hoy capturan tráfico cifrado para descifrarlo en el futuro (*Harvest Now, Decrypt Later*).

---

## Parte C — Acceso con clave ed25519

### 1. Diferencia entre `id_ed25519` y `id_ed25519.pub`
- `~/.ssh/id_ed25519`: Es la **clave privada**. Se genera con 64 rondas de protección KDF (`-a 64`). **NUNCA debe salir de la máquina del administrador ni ser transmitida por la red**. Es el secreto que firma los desafíos criptográficos.
- `~/.ssh/id_ed25519.pub`: Es la **clave pública**. Se distribuye y deposita en los servidores remotos a los que se desea ingresar.

### 2. ¿Qué hace `authorized_keys` y por qué debe tener permisos 600?
- **Función:** Es el archivo en el servidor remoto que contiene el catálogo de claves públicas autorizadas para iniciar sesión en esa cuenta específica.
- **Permisos 600 (`rw-------`):** OpenSSH implementa el mecanismo de verificación estricta *StrictModes*. Si `authorized_keys` o el directorio `.ssh` tuviesen permisos abiertos (como 664 o 777), cualquier usuario local del servidor podría modificar el archivo, agregar su propia clave pública y tomar control de la cuenta. Por este motivo, si `authorized_keys` no posee permisos estrictos `600`, el servidor SSH **aborta el inicio de sesión por clave automáticamente**.

### 3. Prueba `ssh horizonte`
Al ejecutar `ssh horizonte whoami`, el cliente se conectó instantáneamente respondiendo `estudiante` sin solicitar ninguna contraseña, validando la directiva `IdentityFile ~/.ssh/id_ed25519` e `IdentitiesOnly yes` de `~/.ssh/config`.

---

## Parte D — Publicar con SSH

### 1. ¿De quién y de qué grupo quedó `comunicado.html`? ¿Por qué (Lab 2)?
- **Propietario y grupo:** El archivo quedó con dueño **`estudiante`** y grupo **`webadmin`** (`-rwxr-xr-x 1 estudiante webadmin 382 Oct 25 00:46 /srv/horizonte/www/comunicado.html`).
- **Justificación técnica (Lab 2):** En el Laboratorio 2 se aplicó el bit especial **setgid** al directorio web (`chmod 2775 /srv/horizonte/www`, `drwxrwsr-x`). El bit setgid obliga a que cualquier archivo o subdirectorio creado dentro de esa carpeta herede automáticamente el grupo propietario del directorio padre (`webadmin`), en lugar del grupo principal del usuario que ejecuta el comando. Esto permite que cualquier miembro del equipo de administración web pueda editar o actualizar contenidos colaborativamente.

---

## Parte E — Verificación Oficial

Se ejecutó la verificación automatizada oficial mediante `bash verificar_lab10.sh estudiante`, logrando un resultado perfecto de **11 de 11 comprobaciones superadas (100%)**:
1. ✅ Captura TELNET: la contraseña se lee en claro
2. ✅ Captura SSH: contraseña y datos NO se leen
3. ✅ Claves de host propias (no las de la imagen)
4. ✅ known_hosts con la huella real del servidor
5. ✅ Clave del cliente ed25519
6. ✅ Clave pública autorizada en la cuenta de estudiante
7. ✅ Permisos de ~/.ssh (700) y authorized_keys (600)
8. ✅ Acceso con clave y alias 'horizonte' (sin contraseña)
9. ✅ Intercambio de claves híbrido post-cuántico
10. ✅ comunicado.html publicado por scp (dueño estudiante, grupo webadmin)
11. ✅ TELNET desactivado al terminar (puerto 23 cerrado)

---

## Reflexión

### Si un día al conectarte ves "REMOTE HOST IDENTIFICATION HAS CHANGED":

#### Lo que NUNCA debes hacer:
1. **NO ignorar la advertencia ni forzar la conexión**.
2. **NO borrar de inmediato el archivo `known_hosts` con `ssh-keygen -R` a ciegas** sin investigar.
3. **NO ingresar contraseñas ni claves privadas**. Si hay un ataque de intermediario en curso (Man-in-the-Middle por suplantación de IP, envenenamiento ARP o desvío DNS), estarías entregando el control de tus credenciales corporativas al atacante.

#### Lo que SÍ debes hacer:
1. **Abortar la conexión inmediatamente**.
2. **Contactar al equipo de infraestructura o al administrador del servidor por un canal alternativo seguro fuera de banda** (llamada telefónica o mensajería cifrada interna).
3. **Preguntar si el servidor fue reinstalado, formateado o si sus claves SSH fueron regeneradas legítimamente**, y solicitar la nueva huella digital oficial (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).
4. Si la renovación fue legítima y la huella coincide carácter por carácter, recién se elimina la clave antigua de la línea indicada en `known_hosts` y se registra la nueva clave confiable.
