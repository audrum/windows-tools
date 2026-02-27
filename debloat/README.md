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

| N | Opcion | Por defecto | Descripcion |
|---|---|---|---|
| 1 | Deshabilitar telemetria y recopilacion de datos | Si | Desactiva el servicio DiagTrack y establece AllowTelemetry=0 via politica de grupo |
| 2 | Deshabilitar Windows Copilot (Windows 11) | Si | Desactiva Copilot mediante clave de registro en HKCU y HKLM |
| 3 | Deshabilitar Cortana y busqueda web de Bing | Si | Impide que el buscador de Windows consulte la web y desactiva Cortana |
| 4 | Deshabilitar funciones de consumidor | Si | Evita que Windows instale apps automaticamente desde la Tienda (CloudContent) |
| 5 | Eliminar apps UWP innecesarias | Si | Desinstala bloatware preinstalado: Bing, Xbox, Skype, Maps, ZuneMusic y otros |
| 6 | Deshabilitar apps en segundo plano | Si | Impide que las apps de la Tienda ejecuten tareas en segundo plano |
| 7 | Deshabilitar tareas programadas de diagnostico | Si | Desactiva tareas del CEIP, Application Experience y DiskDiagnostic |
| 8 | Optimizar efectos visuales (modo rendimiento) | No | Reduce animaciones y transparencias para liberar recursos de CPU y GPU |
| 9 | Desinstalar OneDrive | No | Ejecuta OneDriveSetup.exe /uninstall y elimina el icono del Explorador de archivos |
| 10 | Deshabilitar Game DVR y Xbox Game Bar | Si | Desactiva la grabacion de pantalla de juegos para reducir overhead en CPU |
| 11 | Deshabilitar historial de actividad y linea de tiempo | Si | Impide que Windows registre y sincronice el historial de actividad del usuario |
| 12 | Desactivar consejos y sugerencias de Windows | Si | Elimina notificaciones de ayuda contextual y funciones de Spotlight |
| 13 | Deshabilitar Wi-Fi Sense | Si | Evita la conexion automatica a redes Wi-Fi abiertas compartidas por contactos |
| 14 | Limpiar opciones del menu contextual | No | Elimina entradas de Compartir y Imprimir en 3D del menu contextual del Explorador |

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
