# Actividad 03: Acceso Remoto Seguro (TELNET vs SSH, SSH Endurecido, SFTP Enjaulado y Fail2ban)

**Universidad Privada Domingo Savio (UPDS)**  
**Facultad de Ingeniería — Carrera de Ingeniería de Sistemas (Sexto Semestre)**  
**Asignatura:** Tecnología Web I (SIS-0150)  
**Docente Titular:** M.Sc. Ing. Jimmy Nataniel Requena Llorentty  

### Equipo Estudiantil (Grupo):
1. **Ketfer Gianella Salazar**
2. **Charles Yourdan Conde**
3. **Brian Calás**
4. **Marco Barriga**
5. **Adaniel Balderrama Orellana**

**Sede:** Santa Cruz de la Sierra — Gestión II-2026  
**Repositorio Oficial:** `https://github.com/Grupo-Kali-Linuxxxx/Acceso-remoto-seguro`

---

## 🎯 Descripción y Alcance de la Actividad

El presente repositorio contiene la implementación práctica, justificaciones técnicas y evidencias de auditoría correspondientes a la **Actividad 03 (Acceso Remoto Seguro)** evaluada sobre los **Laboratorios 10 y 11**:

- **Laboratorio 10 (TELNET vs SSH):** Demostración empírica de "La Prueba del Espía", interceptación de credenciales en texto plano con Wireshark sobre TELNET (puerto 23), comparación contra el tráfico cifrado de SSH (puerto 22), regeneración de claves de host y verificación del intercambio híbrido post-cuántico `sntrup761x25519-sha512@openssh.com`. *(11 de 11 comprobaciones superadas - 100%)*.
- **Laboratorio 11 (SSH Endurecido y SFTP Enjaulado):** Bloqueo total de root (`PermitRootLogin no`), erradicación de contraseñas (`PasswordAuthentication no`), autenticación exclusiva con claves asimétricas Ed25519, jaula chroot para operadores web (`/srv/horizonte` propiedad de `root:root 755`), mitigación perimetral con Fail2ban sobre `nftables` y reenvío de puertos mediante túneles locales SSH (`-L 9081`). *(15 de 15 comprobaciones superadas - 100%)*.

---

## 📂 Estructura del Repositorio

```
Acceso-remoto-seguro/
├── 00_ENTREGABLES_PDF/                      # Entregables oficiales en formato PDF
│   ├── Actividad3_Informe_Tecnico_APA7.pdf  # Informe Técnico en formato APA v7
│   ├── Actividad3_Bitacora_IA_APA7.pdf      # Bitácora Metodológica de Inteligencia Artificial
│   ├── Actividad3_Presentacion.pdf          # Diapositivas de la presentación oral (12 slides)
│   ├── Lab10.pdf                            # Informe de Laboratorio 10
│   └── Lab11.pdf                            # Informe de Laboratorio 11
├── Actividad 3/                             # Documentación fuente de la actividad
│   ├── INFORME_TECNICO_APA7.md              # Fuente Markdown del informe técnico
│   ├── BITACORA_IA_APA7.md                  # Fuente Markdown de la bitácora IA
│   ├── GUIA_DEFENSA_Y_PREGUNTAS.md          # Banco de preguntas para la defensa oral
│   ├── presentacion/index.html              # Presentación interactiva en HTML5/CSS3
│   └── evidencias/                          # Capturas de terminal auténticas
├── lab10/                                   # Scripts y configuraciones del Laboratorio 10
└── lab11/                                   # Scripts, configuraciones de SSHD y Fail2ban del Lab 11
```

---

## 📊 Resultados Oficiales de Auditoría

- **Laboratorio 10:** 11 / 11 verificaciones superadas (`bash /root/lab10/verificar_lab10.sh`).
- **Laboratorio 11:** 15 / 15 verificaciones superadas (`bash /root/lab11/verificar_lab11.sh`).
- **Nivel de Dominio Alcanzado:** Estratégico (10 / 10 Puntos).
