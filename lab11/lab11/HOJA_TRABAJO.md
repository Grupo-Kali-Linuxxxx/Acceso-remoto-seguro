# Laboratorio 11 — Hoja de trabajo: SSH endurecido, SFTP enjaulado, fail2ban y túneles

Nombre: ______________________   Fecha: ___/___/2026

Requisito: Laboratorio 10 completo (acceso con clave `ssh horizonte`). Trabaja como root en el servidor.
⚠️  **Regla de oro:** abre DOS sesiones antes de tocar sshd. Si una se corta, arreglas con la otra.

## Parte A — Auditoría inicial
1. `sshd -T | grep -E 'permitrootlogin|passwordauthentication|kexalgorithms|x11forwarding|loglevel'`: anota los valores.
2. `journalctl -u ssh --since today | grep -c 'Failed\|Invalid'`: en un servidor en internet, ¿cuántos intentos
   esperarías por día? (Investiga "SSH brute force honeypot statistics".)

## Parte B — Endurecer sshd (6 TODO en `ssh/10-horizonte.conf`)
Completa: root, contraseñas, AllowGroups y el bloque `Match Group sftp-web`.
1. ¿Por qué el archivo va en `sshd_config.d/` y por qué ahí "gana la primera aparición"?
2. ¿Qué hace `AuthenticationMethods publickey`? ¿Y `LogLevel VERBOSE`?
3. Mira el comentario de la cabecera: ¿qué pasa con un `# comentario` al final de la línea de `ForceCommand`?

## Parte C — El equipo de comunicación (SFTP enjaulado)
Ejecuta `bash endurecer_ssh.sh <tu_usuario>`. Si la jaula falla:
`journalctl -u ssh | grep chroot` → completa el TODO de `endurecer_ssh.sh`.
1. Copia el error y explica la regla de sshd para las carpetas del chroot.
2. Prueba: `sftp -i ~/.ssh/comunicacion_ed25519 comunicacion@127.0.0.1` → `pwd`, `put`, `chmod 664`, `cd /etc`.
3. `ssh -i ~/.ssh/comunicacion_ed25519 comunicacion@127.0.0.1` → ¿qué responde?

## Parte D — fail2ban (2 TODO en `fail2ban/horizonte-ssh.local`)
1. `fail2ban-client status sshd` → ¿qué dice "Journal matches"? ¿Cómo se llama la unidad de SSH en Ubuntu 24.04?
2. Simula un ataque desde otro equipo (o pide al docente que lo haga) y mira `fail2ban-client status sshd`,
   `nft list set inet f2b-table addr-set-sshd` y `/var/log/fail2ban.log`.
3. Desbloquea: `fail2ban-client set sshd unbanip <IP>`.

## Parte E — Túneles
1. La API de eco del Lab 4 solo escucha en `127.0.0.1:8081`. Desde tu PC:
   `ssh -N -L 9081:127.0.0.1:8081 horizonte` y en otra terminal `curl http://127.0.0.1:9081/eco`.
2. Explica con un dibujo el camino del paquete. ¿Para qué sirven `-D 1080` (SOCKS) y `-J` (salto)?

## Parte F — Verificación
`bash verificar_lab11.sh <tu_usuario>` → objetivo **15 de 15**.

## Reflexión
¿Por qué endurecer SSH con claves y AllowGroups es más importante que cambiar el puerto 22 por otro?
