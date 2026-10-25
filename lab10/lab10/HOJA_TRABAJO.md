# Laboratorio 10 — Hoja de trabajo: TELNET vs SSH, "la prueba del espía"

Nombre: ______________________   Fecha: ___/___/2026

Trabaja en tu servidor del colegio (VM o `horizonte-servidor` en Docker), como root (`sudo -i`).
Usuaria de prueba que crean los scripts: `secretaria` / `Circular2026` (solo para el laboratorio).

## Parte A — La prueba del espía
1. `bash telnet_laboratorio.sh activar` — ¿en qué estado venía TELNET en Ubuntu 24.04? (mira `/etc/inetd.conf`)
2. `bash capturar.sh telnet` y `bash capturar.sh ssh`. Completa:

| | TELNET (puerto 23) | SSH (puerto 22) |
|---|---|---|
| ¿Se lee el usuario? | | |
| ¿Se lee la contraseña? | | |
| ¿Se lee lo que se escribió en la sesión? | | |
| ¿Qué se ve en claro? | | |

3. Abre `resultados/telnet.pcap` en Wireshark (Analizar > Seguir > Flujo TCP): captura la pantalla.
4. `bash telnet_laboratorio.sh desactivar`. ¿Por qué existe todavía TELNET en algunos equipos (routers, impresoras)?

## Parte B — ¿Con quién estoy hablando? (claves de host)
1. `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` — ¿qué dice el comentario al final? ¿Qué problema hay si 30
   estudiantes (o 30 VMs clonadas) tienen la MISMA clave de host?
2. Completa el TODO 1 de `preparar_ssh.sh` (regenerar claves de host).
3. `ssh -v -o BatchMode=yes localhost true 2>&1 | grep kex:` — ¿qué algoritmo de intercambio de claves se negoció?
   Busca qué significa "sntrup761x25519".

## Parte C — Acceso con clave ed25519
Completa los TODO 2 a 4 de `preparar_ssh.sh` y ejecútalo: `bash preparar_ssh.sh <tu_usuario_del_lab2>`.
1. Diferencia entre `id_ed25519` y `id_ed25519.pub`. ¿Cuál nunca sale de tu PC?
2. ¿Qué hace `authorized_keys`? ¿Por qué debe tener permisos 600?
3. Prueba `ssh horizonte`. ¿Te pidió contraseña?

## Parte D — Publicar con SSH
`scp comunicado.html horizonte:/srv/horizonte/www/` y ábrelo en el navegador (https://www.horizonte.internal/comunicado.html).
¿De quién y de qué grupo quedó el archivo? ¿Por qué (Lab 2)? Prueba también `sftp horizonte` y `rsync -av`.

## Parte E — Verificación
`bash verificar_lab10.sh <tu_usuario>` → objetivo **11 de 11**.

## Reflexión
Si un día al conectarte ves "REMOTE HOST IDENTIFICATION HAS CHANGED", ¿qué haces y qué NO haces?
