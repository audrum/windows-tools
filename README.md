# Mantenimiento-Windows.ps1

Script de PowerShell para realizar un mantenimiento completo y automatizado de equipos con **Windows 10 y Windows 11**. Detecta el tipo de almacenamiento instalado (SSD, NVMe o HDD) y adapta los pasos correspondientes. No elimina archivos sensibles ni datos del usuario.

---

## Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10 (build 10240+) o Windows 11 |
| PowerShell | 5.1 o superior (incluido en Windows) |
| Permisos | Debe ejecutarse como **Administrador** |
| Modulo opcional | `PSWindowsUpdate` para instalar actualizaciones automaticamente |

---

## Inicio rapido

1. Abre **PowerShell como Administrador**.
2. Permite la ejecucion del script en la sesion actual:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. Ejecuta el script:
   ```powershell
   .\Mantenimiento-Windows.ps1
   ```

---

## Parametros

| Parametro | Tipo | Descripcion |
|---|---|---|
| `-TodosLosPasos` | Switch | Ejecuta todos los pasos sin mostrar el menu de seleccion |
| `-Pasos` | `int[]` | Lista de numeros de paso a ejecutar (ej. `2,5,6`) |
| `-AutoReiniciar` | Switch | Reinicia el equipo automaticamente al finalizar |
| `-SegundosEspera` | `int` | Segundos de cuenta regresiva antes del reinicio automatico (defecto: `60`) |

---

## Modos de uso

### Menu interactivo (por defecto)

Cuando se ejecuta sin parametros, muestra un menu donde se pueden activar o desactivar los pasos antes de comenzar:

```powershell
.\Mantenimiento-Windows.ps1
```

```
  ====================================================================
   SELECCION DE PASOS  -  Mantenimiento Windows v1.3.1
  ====================================================================

   N   Est  Paso                                      Descripcion
  --------------------------------------------------------------------
    1  [*]  Informacion del sistema (requerido)       Detecta OS, CPU, RAM y tipo de disco
    2  [X]  Limpieza de temporales                    Elimina archivos temporales...
    3  [X]  Limpieza de disco (cleanmgr)              Ejecuta la herramienta integrada...
    4  [X]  Optimizacion de almacenamiento            TRIM para SSD/NVMe o desfrag para HDD
   ...
   15 [X]  Salud de disco (S.M.A.R.T.)               Detecta fallos inminentes por temperatura...
  --------------------------------------------------------------------
  Pasos seleccionados: 15 de 15

  [T] Todos  [N] Ninguno  [ENTER] Ejecutar  [Q] Salir
  >
```

**Controles del menu:**

| Tecla | Accion |
|---|---|
| Numero (1-15) | Activa o desactiva ese paso |
| `T` | Selecciona todos los pasos |
| `N` | Desmarca todos los pasos (excepto el requerido) |
| `ENTER` | Ejecuta con la seleccion actual |
| `Q` | Cancela y sale del script |

---

### Todos los pasos sin menu

```powershell
.\Mantenimiento-Windows.ps1 -TodosLosPasos
```

---

### Pasos especificos por parametro

Util para automatizacion o tareas programadas. El paso 1 siempre se incluye.

```powershell
# Ejecutar solo limpieza, integridad y actualizaciones
.\Mantenimiento-Windows.ps1 -Pasos 2,3,5,6
```

---

### Ejecucion desatendida con reinicio automatico

```powershell
# Todos los pasos + reinicio automatico con 60 segundos de espera
.\Mantenimiento-Windows.ps1 -TodosLosPasos -AutoReiniciar

# Pasos especificos + reinicio en 30 segundos
.\Mantenimiento-Windows.ps1 -Pasos 2,5,7 -AutoReiniciar -SegundosEspera 30
```

---

## Pasos de mantenimiento

| N° | Nombre | Descripcion | SSD/NVMe | HDD |
|---|---|---|---|---|
| 1* | Informacion del sistema | Detecta OS, CPU, RAM y tipo de disco | Si | Si |
| 2 | Limpieza de temporales | Elimina archivos temporales del sistema (`Windows\Temp`) y del usuario (`%TEMP%`), cache de Windows Update, prefetch y minidumps con mas de 2 dias de antiguedad | Si | Si |
| 3 | Limpieza de disco (cleanmgr) | Ejecuta `cleanmgr` en modo silencioso con todas las categorias seguras habilitadas | Si | Si |
| 4 | Optimizacion de almacenamiento | Ejecuta **TRIM** en discos SSD/NVMe y **desfragmentacion** en discos HDD | TRIM | Defrag |
| 5 | Integridad del sistema | Ejecuta `DISM CheckHealth`, `ScanHealth` y `RestoreHealth` (si hay danos), seguido de `SFC /scannow` | Si | Si |
| 6 | Windows Update | Instala actualizaciones pendientes con `PSWindowsUpdate` (si esta disponible) o lista las pendientes via COM | Si | Si |
| 7 | Analisis de seguridad | Actualiza las definiciones de Windows Defender y ejecuta un escaneo rapido | Si | Si |
| 8 | Mantenimiento de red | Vacia la cache de DNS, renueva la direccion IP y restablece el catalogo Winsock | Si | Si |
| 9 | Eventos criticos | Revisa los eventos de nivel Error y Critico de los logs `System` y `Application` de las ultimas 24 horas | Si | Si |
| 10 | Verificacion de disco | Ejecuta `Repair-Volume -Scan` (equivalente a chkdsk) en todos los volumenes NTFS | Si | Si |
| 11 | Programas de inicio | Lista las entradas del registro de inicio y detecta servicios automaticos detenidos | Si | Si |
| 12 | Revision de controladores | Detecta dispositivos con errores o codigos de problema en el Administrador de dispositivos | Si | Si |
| 13 | Configuracion de energia | Verifica el plan de energia activo y genera un informe de salud de bateria en equipos portatiles | Si | Si |
| 14 | Tareas programadas | Dispara las tareas de mantenimiento integradas de Windows (defrag, limpieza, registro, WinSAT, etc.) | Si | Si |
| 15 | Salud de disco (S.M.A.R.T.) | Detecta fallos inminentes analizando temperatura, desgaste (SSD), errores no corregidos, horas de encendido y latencias maximas mediante `Get-StorageReliabilityCounter` | Si | Si |

> **\*** El paso 1 es requerido y siempre se ejecuta. Los demas son opcionales.

---

## Salud de disco S.M.A.R.T. (paso 15)

Usa `Get-StorageReliabilityCounter`, integrado en Windows 10/11, para analizar cada disco fisico sin herramientas externas. Evalua las siguientes metricas con umbrales diferenciados por tipo de disco:

### Temperatura

| Estado | HDD | SSD / NVMe |
|---|---|---|
| Normal | <= 45 °C | <= 60 °C |
| Advertencia | 46 - 55 °C | 61 - 70 °C |
| Critica | > 55 °C | > 70 °C |

### Desgaste de SSD (wear level)

| Estado | Desgaste acumulado |
|---|---|
| Normal | < 70% usado |
| Advertencia - planifica reemplazo | >= 70% usado |
| Critico - reemplazo urgente | >= 90% usado |

### Otros indicadores

| Metrica | Condicion de alerta |
|---|---|
| Errores de lectura no corregidos | Cualquier valor > 0 (critico) |
| Errores de escritura no corregidos | Cualquier valor > 0 (critico) |
| Horas de encendido | > 35 000 h en HDD / > 43 800 h en SSD (informativo) |
| Latencia maxima de lectura/escritura | > 500 ms (advertencia) |
| Estado general de Windows | `Warning` o `Unhealthy` |

El resumen al final del mantenimiento indica si hay **problemas criticos** (considerar reemplazo inmediato), **advertencias** (monitorizar de cerca) o si todos los discos estan en buen estado.

---

## Reinicio al finalizar

Al terminar el mantenimiento el script siempre ofrece la opcion de reiniciar el equipo para aplicar todos los cambios.

### Modo interactivo
Muestra un prompt `[S] Reiniciar ahora / [N] Reiniciar despues`. Si se elige **S**, inicia una cuenta regresiva de **15 segundos** cancelable con cualquier tecla.

### Modo automatico (`-AutoReiniciar`)
Inicia directamente la cuenta regresiva con los segundos configurados en `-SegundosEspera` (defecto: 60). El usuario puede cancelar presionando cualquier tecla en cualquier momento de la cuenta.

---

## Registro de actividad (logs)

Cada ejecucion genera un archivo de log detallado con marca de tiempo:

```
C:\Mantenimiento_Logs\Mantenimiento_2025-06-15_10-30-00.log
```

El log incluye:
- Informacion completa del hardware detectado
- Resultado de cada paso ejecutado u omitido
- Advertencias y errores con mensajes descriptivos
- Resumen final con el estado de cada area
- Ruta al informe de bateria (en equipos portatiles)

---

## Archivos que NO se eliminan

El script esta disenado para ser conservador con los datos del usuario:

- Documentos, imagenes, videos y archivos personales
- Descargas del usuario
- Datos del navegador (historial, contrasenas, marcadores)
- Archivos de aplicaciones instaladas
- Base de datos del registro (solo lectura para revisiones)
- Cualquier archivo fuera de rutas de temporales del sistema

Solo se eliminan archivos en las siguientes rutas seguras:
- `C:\Windows\Temp` - temporales del sistema (>2 dias)
- `%TEMP%` del usuario actual (>2 dias)
- `C:\Windows\SoftwareDistribution\Download` - cache de descarga de Windows Update
- `C:\Windows\Minidump` - volcados de memoria (>30 dias)
- `C:\Windows\Prefetch` - archivos de precarga (>30 dias)
- `C:\ProgramData\Microsoft\Windows\WER\Temp` - temporales de informe de errores

---

## Instalacion del modulo PSWindowsUpdate (opcional)

Para que el paso 6 pueda instalar actualizaciones automaticamente (no solo listarlas), instala el modulo una sola vez:

```powershell
Install-Module PSWindowsUpdate -Force -Scope CurrentUser
```

Sin este modulo el script igualmente detecta y lista las actualizaciones pendientes usando la API COM de Windows Update.

---

## Programar ejecucion automatica con el Programador de tareas

Para ejecutar el mantenimiento de forma desatendida cada semana:

```powershell
$accion  = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"C:\Scripts\Mantenimiento-Windows.ps1`" -TodosLosPasos -AutoReiniciar -SegundosEspera 120"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00AM"

$config  = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration 00:10:00

Register-ScheduledTask `
    -TaskName  "Mantenimiento Semanal Windows" `
    -Action    $accion `
    -Trigger   $trigger `
    -Settings  $config `
    -RunLevel  Highest `
    -Force
```

---

## Compatibilidad con Windows PowerShell 5.1

El script esta guardado en **UTF-8 con BOM** y saltos de linea **CRLF**, que es el formato requerido por Windows PowerShell 5.1. Si el archivo se abre y se guarda con un editor que cambie el encoding (sin BOM o con LF), puede aparecer el siguiente error al ejecutarlo:

```
Missing expression after unary operator '--'
```

Para verificar o corregir el encoding desde PowerShell:

```powershell
# Verificar encoding actual
$bytes = [System.IO.File]::ReadAllBytes('.\Mantenimiento-Windows.ps1')
if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    Write-Host "OK: UTF-8 con BOM"
} else {
    Write-Host "ADVERTENCIA: falta BOM - puede causar errores"
}

# Corregir encoding si es necesario
$content = Get-Content '.\Mantenimiento-Windows.ps1' -Raw
[System.IO.File]::WriteAllText('.\Mantenimiento-Windows.ps1', $content,
    [System.Text.UTF8Encoding]::new($true))  # $true = incluir BOM
```

---

## Version

| Version | Cambios |
|---|---|
| 1.3.1 | Agrega porcentaje de salud del disco similar a HDD Sentinel en el paso 15. Muestra una barra de progreso visual (`[#####-----]`) con color verde/amarillo/rojo segun el estado y lista los factores que reducen la salud (errores, desgaste, temperatura, latencia, uso prolongado) |
| 1.3.0 | Agrega paso 15: verificacion de salud de disco con S.M.A.R.T. Detecta temperatura critica, desgaste de SSD, errores de lectura/escritura no corregidos, horas de encendido y latencias elevadas usando `Get-StorageReliabilityCounter` nativo de Windows |
| 1.2.2 | Corrige error `The property 'Count' cannot be found on this object` al seleccionar [N] Ninguno en el menu. Causa raiz: `OrderedDictionary` siempre usa el indexador posicional (`int`) en PowerShell aunque las claves sean strings, devolviendo `$null` cuando el indice estaba fuera de rango. Solucion definitiva: reemplaza `[ordered]@{}` por un array de hashtables con iteracion directa (`foreach`/`Where-Object`/`ForEach-Object`) eliminando cualquier indexador ambiguo |
| 1.2.1 | Corrige error de indice fuera de rango (`Index was out of range`) en el menu de seleccion de pasos al acceder al paso 14. Causa: `[ordered]@{}` con claves enteras usa indexacion posicional en lugar de por clave. Solucion: claves convertidas a strings. Ademas: encoding corregido a UTF-8 con BOM y CRLF para compatibilidad con Windows PowerShell 5.1 |
| 1.2.0 | Menu interactivo de seleccion de pasos, parametros `-Pasos` y `-TodosLosPasos` |
| 1.1.0 | Opcion de reinicio al finalizar con cuenta regresiva cancelable, parametros `-AutoReiniciar` y `-SegundosEspera` |
| 1.0.0 | Version inicial con los 14 pasos de mantenimiento y deteccion SSD/HDD |
