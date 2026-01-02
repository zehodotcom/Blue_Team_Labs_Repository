# 🛡️ Blue Team Operations & Incident Response Lab

Este repositorio centraliza mis investigaciones técnicas, análisis forense de red y proyectos de automatización (SOAR) aplicados a la ciberdefensa operativa. 

## 🔍 Investigaciones Destacadas

### [PCAP-01] - Compromiso de Servidor Web vía WebShell
Análisis profundo de una intrusión real mediante captura de tráfico.
* **Escenario:** Detección de actividad sospechosa en servidor de producción.
* **Hallazgos:** Explotación de vulnerabilidad de subida de archivos mediante **bypass de doble extensión** (`image.jpg.php`).
* **Impacto:** Exfiltración de `/etc/passwd` confirmada mediante canal C2.
* **Técnicas MITRE:** T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1041 (Exfiltration Over C2 Channel).
* **[Acceder al Informe Detallado →](./PCAP-01/)**

### [En Desarrollo] - Orquestador SOAR con n8n
Automatización del enriquecimiento de IoCs e inteligencia de amenazas.
* **Estado:** Despliegue final previsto para el 05-JAN-2026.
* **Funcionalidad:** Recepción de alertas vía Webhook, enriquecimiento con **AbuseIPDB** y notificación automática por **Telegram/Gmail**.

---
**Contacto:** [LinkedIn](https://www.linkedin.com/in/%C3%A1ngel-garc%C3%ADa-blueteam/)