# GUÍA DE PREPARACIÓN PARA LA DEFENSA ORAL — ACTIVIDAD 3
## Acceso Remoto Seguro: TELNET vs SSH, SSH Endurecido, SFTP Enjaulado, Fail2ban y Túneles

**Asignatura:** Tecnología Web I (SIS-0150)  
**Institución:** Universidad Privada Domingo Savio (UPDS)  
**Docente Evaluador:** M.Sc. Ing. Jimmy Nataniel Requena Llorentty  
**Equipo Estudiantil:** Ketfer Gianella Salazar, Charles Yourdan Conde, Brian Calás, Marco Barriga, Adaniel Balderrama  

---

### Pregunta 1: ¿Por qué TELNET expone datos y SSH no?
- **Respuesta Técnica:**  
  TELNET (RFC 854, 1983) fue diseñado en los albores de Internet cuando las redes eran consideradas de confianza mutua. Carece por completo de mecanismos de cifrado, encapsulación o negociación de claves; los datos viajan directamente sobre la capa de transporte TCP en texto plano (ASCII de 7 u 8 bits). Cualquier atacante ubicado en el mismo segmento de red, switch o punto de enrutamiento puede capturar los paquetes con herramientas como Wireshark o `tcpdump` y reconstruir el flujo TCP íntegro, leyendo usuarios, contraseñas y comandos ejecutados.
  
  En cambio, OpenSSH (RFC 4251) implementa una arquitectura criptográfica en capas:
  1. **Capa de Transporte (SSH-TRANS):** Establece confidencialidad e integridad antes de cualquier autenticación mediante un intercambio de claves Diffie-Hellman (o híbrido post-cuántico `sntrup761x25519-sha512`). A partir de ese momento, todo el tráfico se cifra simétricamente con algoritmos AEAD como ChaCha20-Poly1305 o AES-GCM.
  2. **Capa de Autenticación (SSH-AUTH):** La verificación de credenciales (claves asimétricas) ocurre *dentro* del túnel ya cifrado, por lo que ninguna credencial viaja jamás en texto claro por la red.

---

### Pregunta 2: ¿Cuál es la diferencia entre clave privada, clave pública y `known_hosts`?
- **Respuesta Técnica:**
  - **Clave Privada (`id_ed25519`):** Es el secreto criptográfico que reside **únicamente en el cliente**. Se utiliza para firmar los desafíos de autenticación emitidos por el servidor. Jamás debe salir del equipo local ni compartirse en repositorios, correos o plataformas.
  - **Clave Pública (`id_ed25519.pub`):** Es el componente matemático público derivado de la clave privada. Se transfiere al servidor remoto y se almacena en el archivo `~/.ssh/authorized_keys` del usuario. Permite al servidor verificar matemáticamente que la firma recibida proviene del poseedor de la clave privada legítima.
  - **Archivo `known_hosts` (en el cliente):** Almacena las **claves públicas de host de los servidores** a los que el cliente se ha conectado previamente. Sirve para autenticar la identidad del servidor remoto ante el cliente, evitando que un atacante suplante al servidor (ataque Man-in-the-Middle).

---

### Pregunta 3: ¿Por qué se debe verificar una huella de host cambiada antes de actualizar `known_hosts`?
- **Respuesta Técnica:**
  Cuando OpenSSH despliega la alarma crítica:
  `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`  
  `@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @`  
  Significa que la clave pública que el servidor está presentando hoy no coincide con la huella criptográfica guardada previamente en `~/.ssh/known_hosts`.
  
  Existen dos posibles causas:
  1. **Causa Legítima:** El administrador reinstaló el sistema operativo o regeneró las claves de host (como hicimos en el Lab 10 al eliminar las claves clonadas).
  2. **Ataque Crítico:** Un atacante está ejecutando un ataque de intermediario (*Man-in-the-Middle*), suplantando la dirección IP del servidor para interceptar la sesión.
  
  **Protocolo obligatorio:** NUNCA se debe borrar la advertencia a ciegas con `ssh-keygen -R`. Primero se debe contactar al administrador por un canal seguro fuera de banda (teléfono o presencial) y solicitar la huella oficial generada en el servidor (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Solo si los caracteres de la huella SHA256 coinciden con exactitud, se purga la entrada anterior y se autoriza la nueva identidad.

---

### Pregunta 4: ¿Por qué la raíz del chroot debe pertenecer obligatoriamente a `root:root` con permisos `755`?
- **Respuesta Técnica:**
  OpenSSH implementa una salvaguarda estricta de seguridad en el código de `sshd` para prevenir **escapes de la jaula** (*chroot escape*):
  - Si el directorio definido en `ChrootDirectory` (`/srv/horizonte`) o cualquiera de sus rutas ascendentes (`/srv`, `/`) tuviera permisos de escritura para el grupo u otros usuarios (`chmod 775` o propiedad de `webadmin`), un usuario confinado malicioso podría renombrar carpetas, sustituir librerías del sistema mediante enlaces simbólicos o manipular archivos de configuración para escapar de la jaula y tomar control del sistema operativo anfitrión.
  - Por esta razón, `sshd` verifica con `stat()` que el directorio pertenezca a `root:root` y tenga permisos máximos `755` (o `750`). Si detecta permisos de escritura no autorizados, aborta la conexión con el error: `fatal: bad ownership or modes for chroot directory`.
  - La escritura para los operadores se resuelve creando subdirectorios internos (como `/srv/horizonte/www`) donde sí se otorgan permisos al grupo colaborativo con el bit `setgid`.

---

### Pregunta 5: ¿Qué significan `maxretry`, `findtime` y `bantime` en Fail2ban?
- **Respuesta Técnica:**
  Son los tres parámetros cardinales que definen la ventana temporal y la severidad de la política de mitigación de ataques de fuerza bruta:
  - **`findtime` (ej. `10m` o 600 segundos):** Es la ventana de tiempo durante la cual Fail2ban contabiliza los intentos fallidos provenientes de una misma dirección IP.
  - **`maxretry` (ej. `4` intentos):** Es el número máximo de fallos tolerados dentro de la ventana de `findtime`. Si una IP acumula este número de fallos, se activa la acción de baneo.
  - **`bantime` (ej. `1h` o 3600 segundos):** Es la duración de la penalización durante la cual la IP atacante permanecerá bloqueada en el firewall (`nftables`).
  - **`bantime.increment = true`:** Mecanismo de baneo exponencial que multiplica el `bantime` si la misma IP reincide tras expirar su castigo previo.

---

### Pregunta 6: ¿Por qué recibir un mensaje de "Permission denied" NO basta para demostrar que Fail2ban bloqueó al atacante?
- **Respuesta Técnica:**
  El mensaje `Permission denied (publickey)` es emitido por el daemon **OpenSSH** en el espacio de usuario cuando una clave no coincide o cuando las contraseñas están deshabilitadas; es una respuesta normal de autenticación fallida a nivel de protocolo SSH.
  
  En cambio, un bloqueo efectivo de **Fail2ban** ocurre a nivel de **Kernel y Red (Capa 3 / Capa 4)** a través de `nftables`. Cuando Fail2ban actúa:
  1. En el log `/var/log/fail2ban.log` se registra formalmente el evento: `[sshd] Ban <IP>`.
  2. En `fail2ban-client status sshd` se incrementa el contador `Currently banned: 1` y se lista la IP.
  3. En `nft list set inet f2b-table addr-set-sshd` aparece la dirección IP del atacante.
  4. Una vez bloqueada por `nftables`, los paquetes son descartados (*DROP*): la conexión ya no recibe un `Permission denied`, sino que la conexión se congela por tiempo de espera (*Connection timed out*) o es rechazada de inmediato en el handshake TCP antes de llegar a OpenSSH.

---

### Pregunta 7: ¿Qué evidencias prueban el Ban, su aplicación en `nftables` y la expiración automática?
- **Respuesta Técnica:**
  La evidencia completa consta de una tríada de comprobaciones:
  1. **Evidencia de Ban en registros:** `tail -n 20 /var/log/fail2ban.log` mostrando la línea `Ban <IP_ATACANTE>`.
  2. **Evidencia en Kernel (Nftables):** `nft list set inet f2b-table addr-set-sshd` mostrando la IP dentro de los elementos activos del set (`elements = { 172.22.0.3 }`).
  3. **Evidencia de Expiración Automática (Unban):** Tras transcurrir el `bantime`, el log registra `Unban <IP_ATACANTE>`, `fail2ban-client status sshd` muestra `Currently banned: 0`, y la consulta a `nft list set inet f2b-table addr-set-sshd` confirma que el conjunto ha quedado vacío (`elements = {}`).

---

### Pregunta 8: ¿Qué ventaja tiene un túnel SSH si la API interna escucha únicamente en `127.0.0.1:8081`?
- **Respuesta Técnica:**
  - **Reducción de Superficie de Ataque:** Al enlazar el servicio en `127.0.0.1` (bucle local), la API es invisible desde cualquier tarjeta de red externa; los escáneres de puertos de Internet no pueden detectarla ni atacarla.
  - **Cifrado Fuerte Gratuito:** El microservicio interno puede operar en HTTP plano sin sobrecarga criptográfica interna, ya que todo el tránsito a través de redes inseguras viaja encapsulado en el túnel SSH cifrado con ChaCha20-Poly1305.
  - **Autenticación Centralizada:** No es necesario implementar autenticación y gestión de usuarios compleja en cada microservicio interno; el acceso está protegido por la sólida autenticación asimétrica de claves Ed25519 de OpenSSH.
  - **Flexibilidad Administrativa:** Con el comando `ssh -N -L 9081:127.0.0.1:8081 horizonte`, herramientas locales como navegadores, Postman o scripts de monitoreo pueden consumir la API remota como si estuviera corriendo en su propia máquina.

