# Debloat-Windows.ps1

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue) ![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078d4)

Script interactivo de PowerShell para eliminar bloatware de **Windows 10 y 11** de forma segura, deshabilitar la telemetria y mejorar el rendimiento general sin romper funcionalidades criticas del sistema.

---

## Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10 o Windows 11 |
| PowerShell | 5.1 o superior (incluido en Windows) |
| Permisos | Debe ejecutarse como **Administrador** |

---

## Inicio rapido

### Una linea desde cualquier PowerShell

Abre PowerShell como Administrador y pega:

```powershell
irm run.andresbolivar.me/debloat/run.ps1 | iex
```

El script muestra un menu interactivo donde puedes activar o desactivar cada opcion antes de ejecutarla.

---

## Menu interactivo

Al iniciarse, el script presenta un menu de casillas donde cada opcion puede activarse o desactivarse de forma individual:

```
==========================================================
         Eliminación de bloatware en Windows 10/11
==========================================================

   1 [X] Deshabilitar telemetría y recopilación de datos
   2 [X] Deshabilitar Windows Copilot (Windows 11)
   3 [X] Deshabilitar Cortana (Windows 10) y búsqueda web de Bing
  ...
   8 [ ] Optimizar efectos visuales (modo rendimiento)
   9 [ ] Desinstalar OneDrive
  ...

  Escribe un número para activar/desactivar una opción.
  [A] Seleccionar todo  |  [N] Deseleccionar todo  |  [R] Ejecutar selección  |  [Q] Salir
```

### Controles del menu

| Tecla | Accion |
|---|---|
| Numero (1-14) | Activa o desactiva esa opcion |
| `A` | Selecciona todas las opciones |
| `N` | Desmarca todas las opciones |
| `R` | Ejecuta con la seleccion actual |
| `Q` | Cancela y sale sin realizar cambios |

---

## Opciones disponibles

| N | Opcion | Activa por defecto |
|---|---|---|
| 1 | Deshabilitar telemetria y recopilacion de datos | Si |
| 2 | Deshabilitar Windows Copilot (Windows 11) | Si |
| 3 | Deshabilitar Cortana (Windows 10) y busqueda web de Bing | Si |
| 4 | Deshabilitar funciones de consumidor (instalacion automatica de apps) | Si |
| 5 | Eliminar apps UWP innecesarias (bloatware y Xbox) | Si |
| 6 | Deshabilitar apps en segundo plano | Si |
| 7 | Deshabilitar tareas programadas de diagnostico | Si |
| 8 | Optimizar efectos visuales (modo rendimiento) | No |
| 9 | Desinstalar OneDrive | No |
| 10 | Deshabilitar Game DVR y Xbox Game Bar | Si |
| 11 | Deshabilitar historial de actividad y linea de tiempo | Si |
| 12 | Desactivar consejos, trucos y sugerencias de Windows | Si |
| 13 | Deshabilitar Wi-Fi Sense | Si |
| 14 | Limpiar opciones del menu contextual | No |

---

## Metricas antes y despues

Al ejecutarse, el script captura metricas del sistema antes y despues del proceso para mostrar el impacto real de los cambios:

- Espacio libre en disco `C:`
- Memoria RAM libre
- Numero de procesos en ejecucion
- Carga de CPU
- Conexiones de red establecidas

---

## Registro de actividad (log)

Al finalizar, el script genera un archivo de log con las metricas comparativas y los componentes eliminados:

```
C:\Debloat-Windows\debloat_log.txt
```

El log incluye:
- Espacio en disco libre antes y despues (en GB)
- RAM libre antes y despues (en MB)
- Carga de CPU y numero de procesos antes y despues
- Conexiones de red establecidas antes y despues
- Lista de aplicaciones UWP eliminadas

---

## Reinicio al finalizar

Al terminar, el script ofrece la opcion de reiniciar el equipo para asegurarse de que todos los cambios surtan efecto correctamente.
