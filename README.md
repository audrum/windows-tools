# Windows Tools

Coleccion de scripts de PowerShell para mantenimiento y optimizacion de equipos con **Windows 10 y Windows 11**. Cada herramienta se ejecuta con una sola linea desde cualquier PowerShell.

---

## Herramientas disponibles

| Herramienta | Descripcion | Comando rapido |
|---|---|---|
| [Mantenimiento Windows](mantenimiento/README.md) | Limpieza, reparacion del sistema, actualizaciones y diagnostico completo | `irm run.andresbolivar.me/mantenimiento/run.ps1 \| iex` |
| [Debloat Windows](debloat/README.md) | Eliminacion de aplicaciones preinstaladas y ajustes de privacidad | `irm run.andresbolivar.me/debloat/run.ps1 \| iex` |

---

## Requisitos comunes

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10 (build 10240+) o Windows 11 |
| PowerShell | 5.1 o superior (incluido en Windows) |
| Permisos | Administrador (el lanzador solicita elevacion via UAC automaticamente) |

---

## Uso general

Abre PowerShell (sin necesidad de ejecutarlo como Administrador de antemano) y pega el comando de la herramienta que quieras usar. El lanzador detecta si la sesion no esta elevada, solicita permisos via **UAC** y continua la ejecucion en modo administrador.

Ejemplo:

```powershell
irm run.andresbolivar.me/mantenimiento/run.ps1 | iex
```

El patron `irm ... | iex` descarga el lanzador directamente desde este servidor y lo ejecuta en memoria, sin necesidad de descargar ni desbloquear archivos manualmente.
