#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Script de Mantenimiento Completo para Windows 10 y 11
.DESCRIPTION
    Automatiza el mantenimiento del sistema detectando el tipo de almacenamiento
    (SSD/NVMe/HDD) para aplicar los pasos adecuados. No elimina archivos
    sensibles ni datos de usuario.
.PARAMETER AutoReiniciar
    Si se especifica, reinicia el equipo automaticamente al finalizar
    sin solicitar confirmacion al usuario (util para ejecucion desatendida).
.PARAMETER SegundosEspera
    Segundos de cuenta regresiva antes del reinicio automatico. Por defecto: 60.
.PARAMETER Pasos
    Lista de numeros de paso a ejecutar (separados por coma).
    El paso 1 (informacion del sistema) siempre se ejecuta.
    Si se omite y no se usa -TodosLosPasos, se muestra el menu interactivo.
.PARAMETER TodosLosPasos
    Ejecuta todos los pasos sin mostrar el menu de seleccion.
.EXAMPLE
    .\Mantenimiento-Windows.ps1
    Muestra el menu interactivo para elegir los pasos y pregunta si reiniciar.
.EXAMPLE
    .\Mantenimiento-Windows.ps1 -TodosLosPasos
    Ejecuta todos los pasos directamente sin menu de seleccion.
.EXAMPLE
    .\Mantenimiento-Windows.ps1 -Pasos 2,3,5,6
    Ejecuta solo los pasos 2, 3, 5 y 6 (mas el paso 1, siempre requerido).
.EXAMPLE
    .\Mantenimiento-Windows.ps1 -TodosLosPasos -AutoReiniciar -SegundosEspera 30
    Ejecuta todos los pasos y reinicia automaticamente en 30 segundos.
.NOTES
    Requiere ejecucion como Administrador.
    Compatible con Windows 10 y Windows 11.
#>
param(
    [switch]$AutoReiniciar,
    [int]$SegundosEspera = 60,
    [int[]]$Pasos,
    [switch]$TodosLosPasos
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ============================================================
#  CONFIGURACION GLOBAL
# ============================================================
$Script:Version      = "1.3.1"
$Script:FechaInicio  = Get-Date
$Script:LogDir       = "$env:SystemDrive\Mantenimiento_Logs"
$Script:LogFile      = "$Script:LogDir\Mantenimiento_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$Script:Resumen      = [System.Collections.Generic.List[string]]::new()

# Definicion de pasos disponibles (Requerido=$true = no se puede desmarcar)
# Array de hashtables: evita la ambiguedad de indexacion de OrderedDictionary
$Script:PasosDisponibles = @(
    @{ Numero=1;  Nombre="Informacion del sistema";            Desc="Detecta OS, CPU, RAM y tipo de disco (SSD/HDD)";  Funcion={ Obtener-InfoSistema };         Requerido=$true;  Seleccionado=$true }
    @{ Numero=2;  Nombre="Limpieza de temporales";             Desc="Elimina archivos temporales del sistema y usuario"; Funcion={ Limpiar-Temporales };           Requerido=$false; Seleccionado=$true }
    @{ Numero=3;  Nombre="Limpieza de disco (cleanmgr)";       Desc="Ejecuta la herramienta integrada de limpieza";     Funcion={ Ejecutar-LimpiezaDisco };       Requerido=$false; Seleccionado=$true }
    @{ Numero=4;  Nombre="Optimizacion de almacenamiento";     Desc="TRIM para SSD/NVMe o desfragmentacion para HDD";   Funcion={ Optimizar-Almacenamiento };     Requerido=$false; Seleccionado=$true }
    @{ Numero=5;  Nombre="Integridad del sistema (DISM+SFC)";  Desc="Verifica y repara archivos del sistema";           Funcion={ Verificar-IntegridadSistema };  Requerido=$false; Seleccionado=$true }
    @{ Numero=6;  Nombre="Windows Update";                     Desc="Busca e instala actualizaciones pendientes";        Funcion={ Actualizar-Windows };           Requerido=$false; Seleccionado=$true }
    @{ Numero=7;  Nombre="Analisis de seguridad (Defender)";   Desc="Actualiza firmas y ejecuta escaneo rapido";        Funcion={ Ejecutar-AntivirusScan };       Requerido=$false; Seleccionado=$true }
    @{ Numero=8;  Nombre="Mantenimiento de red";               Desc="Vacia DNS, renueva IP y restablece Winsock";       Funcion={ Mantener-Red };                 Requerido=$false; Seleccionado=$true }
    @{ Numero=9;  Nombre="Eventos criticos del sistema";       Desc="Revisa errores criticos de las ultimas 24 h";      Funcion={ Revisar-EventosCriticos };      Requerido=$false; Seleccionado=$true }
    @{ Numero=10; Nombre="Verificacion de disco (ChkDsk)";     Desc="Comprueba la integridad de volumenes NTFS";        Funcion={ Verificar-ChkDsk };             Requerido=$false; Seleccionado=$true }
    @{ Numero=11; Nombre="Programas y servicios de inicio";    Desc="Lista entradas de inicio y servicios detenidos";   Funcion={ Revisar-Inicio };               Requerido=$false; Seleccionado=$true }
    @{ Numero=12; Nombre="Revision de controladores";          Desc="Detecta dispositivos con errores";                 Funcion={ Revisar-Controladores };        Requerido=$false; Seleccionado=$true }
    @{ Numero=13; Nombre="Configuracion de energia";           Desc="Verifica plan de energia y salud de bateria";      Funcion={ Verificar-Energia };            Requerido=$false; Seleccionado=$true }
    @{ Numero=14; Nombre="Tareas de mantenimiento programado"; Desc="Dispara tareas integradas de mantenimiento";       Funcion={ Ejecutar-TareasMantenimiento }; Requerido=$false; Seleccionado=$true }
    @{ Numero=15; Nombre="Salud de disco (S.M.A.R.T.)";       Desc="Detecta fallos inminentes por temperatura y desgaste"; Funcion={ Verificar-SaludDisco };        Requerido=$false; Seleccionado=$true }
)

# ============================================================
#  FUNCIONES DE UTILIDAD
# ============================================================

function Escribir-Log {
    param(
        [string]$Mensaje,
        [ValidateSet("INFO","OK","WARN","ERROR","SECCION")]
        [string]$Tipo = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $linea = "[$timestamp][$Tipo] $Mensaje"

    # Color en consola
    switch ($Tipo) {
        "OK"      { Write-Host $linea -ForegroundColor Green }
        "WARN"    { Write-Host $linea -ForegroundColor Yellow }
        "ERROR"   { Write-Host $linea -ForegroundColor Red }
        "SECCION" { Write-Host "`n$('=' * 70)`n  $Mensaje`n$('=' * 70)" -ForegroundColor Cyan }
        default   { Write-Host $linea -ForegroundColor White }
    }

    Add-Content -Path $Script:LogFile -Value $linea -Encoding UTF8
}

function Agregar-Resumen {
    param([string]$Entrada)
    $Script:Resumen.Add($Entrada)
}

function Obtener-TamanoLegible {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes Bytes"
}

function Limpiar-DirectorioSeguro {
    <#
        Elimina unicamente archivos (no carpetas raiz) de rutas de temporales
        del sistema. Nunca toca directorios de usuario, documentos, etc.
    #>
    param(
        [string]$Ruta,
        [string]$Descripcion,
        [int]$DiasAntiguedad = 0
    )

    if (-not (Test-Path $Ruta)) {
        Escribir-Log "Ruta no encontrada, omitiendo: $Ruta" -Tipo WARN
        return 0
    }

    $limite = (Get-Date).AddDays(-$DiasAntiguedad)
    $total  = 0

    try {
        $archivos = Get-ChildItem -Path $Ruta -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                ($DiasAntiguedad -eq 0 -or $_.LastWriteTime -lt $limite)
            }

        foreach ($archivo in $archivos) {
            try {
                $total += $archivo.Length
                Remove-Item -Path $archivo.FullName -Force -ErrorAction Stop
            } catch {
                Escribir-Log "No se pudo eliminar: $($archivo.FullName)  -  $($_.Exception.Message)" -Tipo WARN
            }
        }
    } catch {
        Escribir-Log "Error al procesar $Descripcion`: $($_.Exception.Message)" -Tipo ERROR
    }

    Escribir-Log "$Descripcion`: liberados $(Obtener-TamanoLegible $total)" -Tipo OK
    return $total
}

# ============================================================
#  PASO 1  -  INFORMACION DEL SISTEMA
# ============================================================
function Obtener-InfoSistema {
    Escribir-Log "INFORMACION DEL SISTEMA" -Tipo SECCION

    # Sistema operativo
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    $nombreOS = if ($build -ge 22000) { "Windows 11" } else { "Windows 10" }

    Escribir-Log "Sistema operativo : $nombreOS ($($os.Caption))  -  Build $build"
    Escribir-Log "Version           : $($os.Version)"
    Escribir-Log "Arquitectura      : $($os.OSArchitecture)"

    # RAM
    $ramTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $ramLibre  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    Escribir-Log "RAM Total         : $ramTotal GB  |  Libre: $ramLibre GB"

    # CPU
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    Escribir-Log "Procesador        : $($cpu.Name.Trim())"
    Escribir-Log "Nucleos / Hilos   : $($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)"

    # Discos fisicos
    Escribir-Log "--- Discos fisicos detectados ---"
    $Script:Discos = @{}

    Get-PhysicalDisk | ForEach-Object {
        $disco = $_
        $mediaType = switch ($disco.MediaType) {
            "SSD"         { "SSD" }
            "SCM"         { "NVMe/SCM" }
            "HDD"         { "HDD" }
            default {
                # Intentar inferir por BusType cuando MediaType es "Unspecified"
                if ($disco.BusType -in @("NVMe","RAID")) { "SSD/NVMe (inferido)" }
                elseif ($disco.SpindleSpeed -gt 0)        { "HDD (inferido)" }
                else                                       { "SSD (inferido)" }
            }
        }
        $Script:Discos[$disco.DeviceId] = $mediaType
        Escribir-Log ("  Disco {0}: {1}  -  {2}  -  {3}" -f $disco.DeviceId, $disco.FriendlyName, $mediaType, (Obtener-TamanoLegible ($disco.Size)))
    }

    # Volumen del sistema
    $letraSistema = $env:SystemDrive[0]
    try {
        $particion   = Get-Partition -DriveLetter $letraSistema -ErrorAction Stop
        $discoSistema = Get-PhysicalDisk | Where-Object DeviceId -eq $particion.DiskNumber | Select-Object -First 1
        $Script:TipoDiscoSistema = $Script:Discos[$discoSistema.DeviceId]
    } catch {
        $Script:TipoDiscoSistema = "SSD (inferido)"
        Escribir-Log "No se pudo determinar el tipo de disco del sistema, asumiendo SSD." -Tipo WARN
    }

    Escribir-Log "Disco del sistema : $Script:TipoDiscoSistema  (unidad $letraSistema`:)"

    # Espacio en disco del sistema
    $volumen = Get-PSDrive -Name $letraSistema -ErrorAction SilentlyContinue
    if ($volumen) {
        $usado  = Obtener-TamanoLegible (($volumen.Used) * 1)
        $libre  = Obtener-TamanoLegible (($volumen.Free) * 1)
        Escribir-Log "Espacio en $letraSistema`:  Usado: $usado  |  Libre: $libre"
    }

    Agregar-Resumen "Sistema: $nombreOS | Disco sistema: $Script:TipoDiscoSistema | RAM: $ramTotal GB"
}

# ============================================================
#  PASO 2  -  LIMPIEZA DE ARCHIVOS TEMPORALES
# ============================================================
function Limpiar-Temporales {
    Escribir-Log "LIMPIEZA DE ARCHIVOS TEMPORALES" -Tipo SECCION

    $totalLiberado = 0

    # Temp del sistema (Windows\Temp)  -  solo archivos con mas de 2 dias
    $totalLiberado += Limpiar-DirectorioSeguro `
        -Ruta "$env:SystemRoot\Temp" `
        -Descripcion "Temporales del sistema (Windows\Temp)" `
        -DiasAntiguedad 2

    # Temp del usuario actual  -  solo archivos con mas de 2 dias
    $totalLiberado += Limpiar-DirectorioSeguro `
        -Ruta $env:TEMP `
        -Descripcion "Temporales del usuario ($env:USERNAME)" `
        -DiasAntiguedad 2

    # Carpeta de descarga de Windows Update (solo contenido de Download)
    $totalLiberado += Limpiar-DirectorioSeguro `
        -Ruta "$env:SystemRoot\SoftwareDistribution\Download" `
        -Descripcion "Cache de descarga de Windows Update" `
        -DiasAntiguedad 0

    # Archivos de volcado de memoria (minidumps del sistema, no de usuario)
    $totalLiberado += Limpiar-DirectorioSeguro `
        -Ruta "$env:SystemRoot\Minidump" `
        -Descripcion "Minidumps del sistema" `
        -DiasAntiguedad 30

    # Reportes de errores de Windows (WER  -  solo los temporales)
    $totalLiberado += Limpiar-DirectorioSeguro `
        -Ruta "$env:ProgramData\Microsoft\Windows\WER\Temp" `
        -Descripcion "Temporales de informe de errores de Windows" `
        -DiasAntiguedad 0

    # Prefetch  -  seguro limpiar (Windows lo reconstruye; no aplica en SSD con ReadyBoost)
    $totalLiberado += Limpiar-DirectorioSeguro `
        -Ruta "$env:SystemRoot\Prefetch" `
        -Descripcion "Prefetch" `
        -DiasAntiguedad 30

    Escribir-Log "Total liberado en temporales: $(Obtener-TamanoLegible $totalLiberado)" -Tipo OK
    Agregar-Resumen "Temporales eliminados: $(Obtener-TamanoLegible $totalLiberado)"
}

# ============================================================
#  PASO 3  -  LIMPIEZA DE DISCO (herramienta integrada cleanmgr)
# ============================================================
function Ejecutar-LimpiezaDisco {
    Escribir-Log "LIMPIEZA DE DISCO (cleanmgr)" -Tipo SECCION

    # Configurar todas las categorias seguras de cleanmgr via registro
    $volumen = $env:SystemDrive[0]
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

    $categorias = @(
        "Active Setup Temp Folders"
        "BranchCache"
        "D3D Shader Cache"
        "Delivery Optimization Files"
        "Downloaded Program Files"
        "Internet Cache Files"
        "Language Pack"
        "Memory Dump Files"
        "Old ChkDsk Files"
        "Previous Installations"
        "Recycle Bin"
        "Service Pack Cleanup"
        "Setup Log Files"
        "System error memory dump files"
        "System error minidump files"
        "Temporary Files"
        "Temporary Setup Files"
        "Thumbnail Cache"
        "Update Cleanup"
        "Upgrade Discarded Files"
        "Windows Error Reporting Files"
        "Windows ESD installation files"
        "Windows Upgrade Log Files"
    )

    foreach ($cat in $categorias) {
        $clave = Join-Path $regPath $cat
        if (Test-Path $clave) {
            try {
                Set-ItemProperty -Path $clave -Name StateFlags0042 -Value 2 -Type DWord -ErrorAction SilentlyContinue
            } catch { }
        }
    }

    Escribir-Log "Ejecutando cleanmgr en modo silencioso (puede tardar varios minutos)..." -Tipo INFO
    try {
        $proc = Start-Process -FilePath "cleanmgr.exe" `
            -ArgumentList "/sagerun:42" `
            -Wait -PassThru -WindowStyle Hidden
        if ($proc.ExitCode -eq 0) {
            Escribir-Log "Limpieza de disco completada correctamente." -Tipo OK
        } else {
            Escribir-Log "cleanmgr finalizo con codigo: $($proc.ExitCode)" -Tipo WARN
        }
    } catch {
        Escribir-Log "No se pudo ejecutar cleanmgr: $($_.Exception.Message)" -Tipo ERROR
    }

    Agregar-Resumen "Limpieza de disco (cleanmgr): completada"
}

# ============================================================
#  PASO 4  -  OPTIMIZACION DE ALMACENAMIENTO (SSD vs HDD)
# ============================================================
function Optimizar-Almacenamiento {
    Escribir-Log "OPTIMIZACION DE ALMACENAMIENTO" -Tipo SECCION

    $esSSD = $Script:TipoDiscoSistema -notlike "*HDD*"

    if ($esSSD) {
        Escribir-Log "Disco SSD/NVMe detectado  -  se ejecutara TRIM (no desfragmentacion)." -Tipo INFO
    } else {
        Escribir-Log "Disco HDD detectado  -  se ejecutara desfragmentacion." -Tipo INFO
    }

    # Procesar todos los volumenes fijos del sistema
    $volumenes = Get-Volume | Where-Object {
        $_.DriveType -eq "Fixed" -and
        $_.DriveLetter -ne $null -and
        $_.FileSystemType -eq "NTFS"
    }

    foreach ($vol in $volumenes) {
        $letra = $vol.DriveLetter

        # Determinar tipo de disco del volumen
        try {
            $particion = Get-Partition -DriveLetter $letra -ErrorAction Stop
            $discoFisico = Get-PhysicalDisk | Where-Object DeviceId -eq $particion.DiskNumber | Select-Object -First 1
            $tipoEsteVol = $Script:Discos[$discoFisico.DeviceId]
            $esSSDEsteVol = $tipoEsteVol -notlike "*HDD*"
        } catch {
            $esSSDEsteVol = $esSSD
            $tipoEsteVol  = $Script:TipoDiscoSistema
        }

        Escribir-Log "Procesando unidad $letra`: ($tipoEsteVol)..." -Tipo INFO

        try {
            if ($esSSDEsteVol) {
                # TRIM  -  no desfragmentar SSD
                Optimize-Volume -DriveLetter $letra -ReTrim -Verbose *>&1 |
                    ForEach-Object { Escribir-Log "  $_" -Tipo INFO }
                Escribir-Log "TRIM ejecutado en $letra`:" -Tipo OK
            } else {
                # Analizar primero
                $analisis = Optimize-Volume -DriveLetter $letra -Analyze -Verbose 2>&1
                Escribir-Log "  Analisis HDD $letra`: $analisis" -Tipo INFO

                # Desfragmentar
                Optimize-Volume -DriveLetter $letra -Defrag -Verbose *>&1 |
                    ForEach-Object { Escribir-Log "  $_" -Tipo INFO }
                Escribir-Log "Desfragmentacion completada en $letra`:" -Tipo OK
            }
        } catch {
            Escribir-Log "Error al optimizar $letra`:: $($_.Exception.Message)" -Tipo ERROR
        }
    }

    Agregar-Resumen "Optimizacion de almacenamiento: completada ($(if ($esSSD) {'TRIM'} else {'Desfragmentacion'}))"
}

# ============================================================
#  PASO 5  -  VERIFICACION DE INTEGRIDAD DEL SISTEMA (DISM + SFC)
# ============================================================
function Verificar-IntegridadSistema {
    Escribir-Log "VERIFICACION DE INTEGRIDAD DEL SISTEMA" -Tipo SECCION

    # --- DISM ---
    Escribir-Log "Ejecutando DISM CheckHealth..." -Tipo INFO
    $dism1 = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1
    $dism1 | ForEach-Object { Escribir-Log "  DISM: $_" -Tipo INFO }

    Escribir-Log "Ejecutando DISM ScanHealth (puede tardar varios minutos)..." -Tipo INFO
    $dism2 = & dism.exe /Online /Cleanup-Image /ScanHealth 2>&1
    $dism2 | ForEach-Object { Escribir-Log "  DISM: $_" -Tipo INFO }

    # Si hay componentes corruptos, restaurar
    if ($dism2 -match "repairable|corrupt|corrup") {
        Escribir-Log "Se detectaron componentes danados. Ejecutando DISM RestoreHealth..." -Tipo WARN
        $dism3 = & dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1
        $dism3 | ForEach-Object { Escribir-Log "  DISM Restore: $_" -Tipo INFO }
        Agregar-Resumen "DISM: se repararon componentes del sistema"
    } else {
        Escribir-Log "DISM: imagen del sistema sin errores detectados." -Tipo OK
        Agregar-Resumen "DISM: sin errores"
    }

    # --- SFC ---
    Escribir-Log "Ejecutando SFC /scannow (puede tardar varios minutos)..." -Tipo INFO
    $sfcOutput = & sfc.exe /scannow 2>&1
    $sfcOutput | ForEach-Object { Escribir-Log "  SFC: $_" -Tipo INFO }

    if ($sfcOutput -match "no encontro ninguna|did not find any|no integrity violations") {
        Escribir-Log "SFC: no se encontraron violaciones de integridad." -Tipo OK
        Agregar-Resumen "SFC: sin errores"
    } elseif ($sfcOutput -match "reparo|repaired|corrected") {
        Escribir-Log "SFC: se repararon archivos del sistema." -Tipo OK
        Agregar-Resumen "SFC: archivos reparados"
    } else {
        Escribir-Log "SFC: revisa el log de CBS para mas detalles." -Tipo WARN
        Agregar-Resumen "SFC: revisar log de CBS en C:\Windows\Logs\CBS\CBS.log"
    }
}

# ============================================================
#  PASO 6  -  WINDOWS UPDATE
# ============================================================
function Actualizar-Windows {
    Escribir-Log "WINDOWS UPDATE" -Tipo SECCION

    # Verificar si el modulo PSWindowsUpdate esta disponible
    $moduloDisponible = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue

    if ($moduloDisponible) {
        Escribir-Log "Modulo PSWindowsUpdate encontrado. Buscando actualizaciones..." -Tipo INFO
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop

            $pendientes = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -ErrorAction Stop
            if ($pendientes.Count -eq 0) {
                Escribir-Log "No hay actualizaciones pendientes." -Tipo OK
                Agregar-Resumen "Windows Update: sin actualizaciones pendientes"
            } else {
                Escribir-Log "Se encontraron $($pendientes.Count) actualizacion(es). Instalando..." -Tipo INFO
                Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop |
                    ForEach-Object { Escribir-Log "  WU: $($_.Title)  -  $($_.Status)" -Tipo INFO }
                Escribir-Log "Actualizaciones instaladas. Puede ser necesario reiniciar." -Tipo OK
                Agregar-Resumen "Windows Update: $($pendientes.Count) actualizacion(es) instalada(s)  -  reinicio pendiente"
            }
        } catch {
            Escribir-Log "Error con PSWindowsUpdate: $($_.Exception.Message)" -Tipo ERROR
            Agregar-Resumen "Windows Update: error  -  revisar log"
        }
    } else {
        # Alternativa: usar el servicio de Windows Update via COM
        Escribir-Log "Modulo PSWindowsUpdate no disponible. Iniciando busqueda via servicio de Windows Update..." -Tipo WARN
        Escribir-Log "Para instalacion automatica, ejecuta: Install-Module PSWindowsUpdate -Force" -Tipo INFO

        try {
            $actualizador  = New-Object -ComObject Microsoft.Update.Session
            $buscador      = $actualizador.CreateUpdateSearcher()
            $resultado     = $buscador.Search("IsInstalled=0 and Type='Software'")
            $total         = $resultado.Updates.Count

            if ($total -eq 0) {
                Escribir-Log "No hay actualizaciones pendientes." -Tipo OK
                Agregar-Resumen "Windows Update: sin actualizaciones pendientes"
            } else {
                Escribir-Log "Se encontraron $total actualizacion(es) pendientes:" -Tipo WARN
                for ($i = 0; $i -lt $total; $i++) {
                    Escribir-Log "  - $($resultado.Updates.Item($i).Title)" -Tipo WARN
                }
                Agregar-Resumen "Windows Update: $total actualizacion(es) pendientes  -  instalar manualmente o con PSWindowsUpdate"
            }
        } catch {
            Escribir-Log "No se pudo consultar Windows Update: $($_.Exception.Message)" -Tipo ERROR
            Agregar-Resumen "Windows Update: no se pudo verificar"
        }
    }
}

# ============================================================
#  PASO 7  -  WINDOWS DEFENDER (analisis rapido)
# ============================================================
function Ejecutar-AntivirusScan {
    Escribir-Log "ANALISIS DE SEGURIDAD (Windows Defender)" -Tipo SECCION

    try {
        # Actualizar definiciones primero
        Escribir-Log "Actualizando definiciones de Windows Defender..." -Tipo INFO
        Update-MpSignature -ErrorAction Stop
        Escribir-Log "Definiciones actualizadas correctamente." -Tipo OK
    } catch {
        Escribir-Log "No se pudieron actualizar las definiciones: $($_.Exception.Message)" -Tipo WARN
    }

    try {
        Escribir-Log "Iniciando analisis rapido del sistema..." -Tipo INFO
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Escribir-Log "Analisis rapido completado." -Tipo OK

        $historial = Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($historial) {
            $reciente = $historial | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5
            Escribir-Log "Amenazas detectadas recientemente:" -Tipo WARN
            $reciente | ForEach-Object {
                Escribir-Log "  [$($_.InitialDetectionTime)] $($_.ThreatName)  -  $($_.Resources)" -Tipo WARN
            }
            Agregar-Resumen "Defender: amenazas detectadas  -  revisar log"
        } else {
            Escribir-Log "No se detectaron amenazas." -Tipo OK
            Agregar-Resumen "Defender: sin amenazas detectadas"
        }
    } catch {
        Escribir-Log "Error al ejecutar el analisis: $($_.Exception.Message)" -Tipo ERROR
        Agregar-Resumen "Defender: error en analisis  -  revisar log"
    }
}

# ============================================================
#  PASO 8  -  RED (flush DNS, reset de pila de red)
# ============================================================
function Mantener-Red {
    Escribir-Log "MANTENIMIENTO DE RED" -Tipo SECCION

    try {
        Escribir-Log "Vaciando cache de DNS..." -Tipo INFO
        Clear-DnsClientCache -ErrorAction Stop
        Escribir-Log "Cache de DNS vaciada correctamente." -Tipo OK
    } catch {
        Escribir-Log "Error al vaciar DNS: $($_.Exception.Message)" -Tipo ERROR
    }

    try {
        Escribir-Log "Liberando y renovando direccion IP..." -Tipo INFO
        & ipconfig /release | Out-Null
        & ipconfig /renew  | Out-Null
        Escribir-Log "Direccion IP renovada." -Tipo OK
    } catch {
        Escribir-Log "Error al renovar IP (puede ser normal en conexiones estaticas)." -Tipo WARN
    }

    try {
        Escribir-Log "Restableciendo catalogo de Winsock..." -Tipo INFO
        & netsh winsock reset | Out-Null
        Escribir-Log "Winsock restablecido (requiere reinicio para aplicar)." -Tipo OK
    } catch {
        Escribir-Log "Error al restablecer Winsock: $($_.Exception.Message)" -Tipo ERROR
    }

    Agregar-Resumen "Red: DNS vaciado, IP renovada, Winsock restablecido"
}

# ============================================================
#  PASO 9  -  REVISION DE LOGS DE EVENTOS CRITICOS
# ============================================================
function Revisar-EventosCriticos {
    Escribir-Log "REVISION DE EVENTOS CRITICOS DEL SISTEMA (ultimas 24 h)" -Tipo SECCION

    $desde = (Get-Date).AddHours(-24)

    foreach ($log in @("System", "Application")) {
        try {
            $eventos = Get-WinEvent -FilterHashtable @{
                LogName   = $log
                Level     = 1, 2      # 1=Critical, 2=Error
                StartTime = $desde
            } -MaxEvents 20 -ErrorAction SilentlyContinue

            if ($eventos) {
                Escribir-Log "  [$log] $($eventos.Count) error(es)/critico(s) en las ultimas 24 h:" -Tipo WARN
                $eventos | Select-Object -First 10 | ForEach-Object {
                    Escribir-Log ("    [{0}] ID {1}: {2}" -f $_.TimeCreated.ToString("HH:mm:ss"), $_.Id, ($_.Message -split "`n")[0]) -Tipo WARN
                }
            } else {
                Escribir-Log "  [$log] Sin eventos criticos en las ultimas 24 h." -Tipo OK
            }
        } catch {
            Escribir-Log "  No se pudo leer el log $log`: $($_.Exception.Message)" -Tipo WARN
        }
    }

    Agregar-Resumen "Eventos: revision completada (ver log para detalles)"
}

# ============================================================
#  PASO 10  -  VERIFICACION DE ESTADO DE CHKDSK
# ============================================================
function Verificar-ChkDsk {
    Escribir-Log "VERIFICACION DE ESTADO DE DISCO (chkdsk)" -Tipo SECCION

    $volumenes = Get-Volume | Where-Object {
        $_.DriveType -eq "Fixed" -and
        $_.DriveLetter -ne $null -and
        $_.FileSystemType -eq "NTFS"
    }

    foreach ($vol in $volumenes) {
        $letra = $vol.DriveLetter
        try {
            Escribir-Log "Verificando estado de $letra`:" -Tipo INFO
            $resultado = Repair-Volume -DriveLetter $letra -Scan -ErrorAction Stop
            switch ($resultado) {
                "NoErrorsFound"    { Escribir-Log "  $letra`: Sin errores detectados." -Tipo OK }
                "ErrorsFound"      { Escribir-Log "  $letra`: Se detectaron errores. Se recomienda ejecutar chkdsk /f en el proximo reinicio." -Tipo WARN }
                "ErrorsFoundFixed" { Escribir-Log "  $letra`: Errores encontrados y corregidos." -Tipo OK }
                default            { Escribir-Log "  $letra`: Resultado: $resultado" -Tipo INFO }
            }
        } catch {
            Escribir-Log "  No se pudo escanear $letra`:: $($_.Exception.Message)" -Tipo WARN
        }
    }

    Agregar-Resumen "ChkDsk: revision completada"
}

# ============================================================
#  PASO 11  -  SERVICIOS Y PROGRAMAS DE INICIO
# ============================================================
function Revisar-Inicio {
    Escribir-Log "REVISION DE PROGRAMAS Y SERVICIOS DE INICIO" -Tipo SECCION

    # Programas de inicio del registro (solo listar, no modificar)
    $rutas = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($ruta in $rutas) {
        if (Test-Path $ruta) {
            $items = Get-ItemProperty -Path $ruta -ErrorAction SilentlyContinue
            if ($items) {
                Escribir-Log "  Entradas de inicio en: $ruta" -Tipo INFO
                $items.PSObject.Properties |
                    Where-Object { $_.Name -notlike "PS*" } |
                    ForEach-Object { Escribir-Log "    $($_.Name): $($_.Value)" -Tipo INFO }
            }
        }
    }

    # Servicios en estado de error
    $serviciosError = Get-Service | Where-Object { $_.Status -eq "StoppedButShouldStart" -or ($_.StartType -eq "Automatic" -and $_.Status -eq "Stopped") } |
        Where-Object { $_.Name -notlike "clr_*" }

    if ($serviciosError) {
        Escribir-Log "Servicios automaticos que no estan corriendo:" -Tipo WARN
        $serviciosError | ForEach-Object {
            Escribir-Log "  $($_.Name) ($($_.DisplayName))" -Tipo WARN
        }
        Agregar-Resumen "Inicio: $($serviciosError.Count) servicio(s) detenidos  -  revisar log"
    } else {
        Escribir-Log "Todos los servicios automaticos estan en ejecucion." -Tipo OK
        Agregar-Resumen "Inicio: servicios OK"
    }
}

# ============================================================
#  PASO 12  -  ACTUALIZACION DE CONTROLADORES (informativo)
# ============================================================
function Revisar-Controladores {
    Escribir-Log "REVISION DE CONTROLADORES (dispositivos con problemas)" -Tipo SECCION

    try {
        $problemDevices = Get-PnpDevice | Where-Object {
            $_.Status -in @("Error", "Degraded", "Unknown") -or
            $_.ConfigManagerErrorCode -ne 0
        }

        if ($problemDevices) {
            Escribir-Log "Dispositivos con problemas detectados:" -Tipo WARN
            $problemDevices | ForEach-Object {
                Escribir-Log "  [$($_.Status)] $($_.FriendlyName)  -  Codigo: $($_.ConfigManagerErrorCode)" -Tipo WARN
            }
            Agregar-Resumen "Controladores: $($problemDevices.Count) dispositivo(s) con problemas  -  revisar Administrador de Dispositivos"
        } else {
            Escribir-Log "Todos los dispositivos funcionan correctamente." -Tipo OK
            Agregar-Resumen "Controladores: todos OK"
        }
    } catch {
        Escribir-Log "No se pudo verificar dispositivos: $($_.Exception.Message)" -Tipo ERROR
        Agregar-Resumen "Controladores: no se pudo verificar"
    }
}

# ============================================================
#  PASO 13  -  CONFIGURACION DE ENERGIA
# ============================================================
function Verificar-Energia {
    Escribir-Log "CONFIGURACION DE ENERGIA" -Tipo SECCION

    try {
        $planActivo = & powercfg /getactivescheme 2>&1
        Escribir-Log "Plan de energia activo: $planActivo" -Tipo INFO

        # Si es laptop, verificar configuracion de bateria
        $bateria = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
        if ($bateria) {
            Escribir-Log "Bateria detectada: $($bateria.Name)" -Tipo INFO
            Escribir-Log "Carga actual: $($bateria.EstimatedChargeRemaining)%" -Tipo INFO
            Escribir-Log "Estado: $($bateria.BatteryStatus)" -Tipo INFO

            # Informe de salud de bateria
            Escribir-Log "Generando informe de bateria..." -Tipo INFO
            $reportePath = "$Script:LogDir\bateria_$(Get-Date -Format 'yyyyMMdd').html"
            & powercfg /batteryreport /output $reportePath 2>&1 | Out-Null
            if (Test-Path $reportePath) {
                Escribir-Log "Informe de bateria guardado en: $reportePath" -Tipo OK
            }
        }

        Agregar-Resumen "Energia: plan verificado"
    } catch {
        Escribir-Log "Error al verificar configuracion de energia: $($_.Exception.Message)" -Tipo ERROR
    }
}

# ============================================================
#  PASO 14  -  TAREAS DE MANTENIMIENTO PROGRAMADAS DE WINDOWS
# ============================================================
function Ejecutar-TareasMantenimiento {
    Escribir-Log "TAREAS DE MANTENIMIENTO PROGRAMADO DE WINDOWS" -Tipo SECCION

    $tareas = @(
        "\Microsoft\Windows\Defrag\ScheduledDefrag",
        "\Microsoft\Windows\DiskCleanup\SilentCleanup",
        "\Microsoft\Windows\Diagnosis\Scheduled",
        "\Microsoft\Windows\Registry\RegIdleBackup",
        "\Microsoft\Windows\ApplicationData\CleanupTemporaryState",
        "\Microsoft\Windows\Maintenance\WinSAT"
    )

    foreach ($tarea in $tareas) {
        try {
            $t = Get-ScheduledTask -TaskPath (Split-Path $tarea) `
                                   -TaskName  (Split-Path $tarea -Leaf) `
                                   -ErrorAction SilentlyContinue
            if ($t) {
                Start-ScheduledTask -TaskPath (Split-Path $tarea) `
                                    -TaskName  (Split-Path $tarea -Leaf) `
                                    -ErrorAction SilentlyContinue
                Escribir-Log "  Tarea iniciada: $tarea" -Tipo OK
            }
        } catch {
            Escribir-Log "  No se pudo iniciar tarea $tarea`: $($_.Exception.Message)" -Tipo WARN
        }
    }

    Agregar-Resumen "Tareas programadas: ejecutadas"
}

# ============================================================
#  HELPER  -  CALCULO DE PORCENTAJE DE SALUD DEL DISCO
# ============================================================
function Calcular-PorcentajeSalud {
    param(
        $Disco,   # PhysicalDisk object
        $Smart    # StorageReliabilityCounter object (puede ser $null)
    )

    $salud    = 100
    $factores = [System.Collections.Generic.List[string]]::new()

    # 1. Estado general reportado por Windows
    switch ($Disco.HealthStatus) {
        "Unhealthy" {
            $salud = [math]::Min($salud, 10)
            $factores.Add("Estado Windows: No saludable")
        }
        "Warning" {
            $salud = [math]::Min($salud, 65)
            $factores.Add("Estado Windows: Advertencia")
        }
    }

    if ($null -ne $Smart) {
        $esHDD = $Disco.MediaType -eq "HDD"

        # 2. Errores no corregidos (impacto alto: -25% por tipo)
        if ($null -ne $Smart.ReadErrorsUncorrected -and $Smart.ReadErrorsUncorrected -gt 0) {
            $salud -= 25
            $factores.Add("Errores de lectura no corregidos: $($Smart.ReadErrorsUncorrected)")
        }
        if ($null -ne $Smart.WriteErrorsUncorrected -and $Smart.WriteErrorsUncorrected -gt 0) {
            $salud -= 25
            $factores.Add("Errores de escritura no corregidos: $($Smart.WriteErrorsUncorrected)")
        }

        # 3. Desgaste SSD/NVMe
        if ($null -ne $Smart.Wear -and $Smart.Wear -gt 0) {
            if ($Smart.Wear -ge 90) {
                $salud = [math]::Min($salud, 100 - $Smart.Wear)
                $factores.Add("Desgaste critico: $($Smart.Wear)% usado")
            } elseif ($Smart.Wear -ge 70) {
                $salud -= 15
                $factores.Add("Desgaste elevado: $($Smart.Wear)% usado")
            }
        }

        # 4. Temperatura
        if ($null -ne $Smart.Temperature -and $Smart.Temperature -gt 0) {
            $limCrit = if ($esHDD) { 55 } else { 70 }
            $limWarn = if ($esHDD) { 45 } else { 60 }
            if ($Smart.Temperature -ge $limCrit) {
                $salud -= 20
                $factores.Add("Temperatura critica: $($Smart.Temperature) C")
            } elseif ($Smart.Temperature -ge $limWarn) {
                $salud -= 10
                $factores.Add("Temperatura elevada: $($Smart.Temperature) C")
            }
        }

        # 5. Latencias maximas
        $latMax = 0
        if ($null -ne $Smart.ReadLatencyMax)  { $latMax = [math]::Max($latMax, $Smart.ReadLatencyMax) }
        if ($null -ne $Smart.WriteLatencyMax) { $latMax = [math]::Max($latMax, $Smart.WriteLatencyMax) }
        if ($latMax -gt 1000) {
            $salud -= 10
            $factores.Add("Latencia muy alta: $latMax ms")
        } elseif ($latMax -gt 500) {
            $salud -= 5
            $factores.Add("Latencia elevada: $latMax ms")
        }

        # 6. Horas de encendido (impacto informativo: -5%)
        if ($null -ne $Smart.PowerOnHours -and $Smart.PowerOnHours -gt 0) {
            $limHoras = if ($esHDD) { 35000 } else { 43800 }
            if ($Smart.PowerOnHours -gt $limHoras) {
                $salud -= 5
                $factores.Add("Uso prolongado: $($Smart.PowerOnHours) h")
            }
        }
    }

    $salud  = [math]::Max(0, [math]::Min(100, $salud))
    $estado = if ($salud -ge 80) { "Bueno" } elseif ($salud -ge 50) { "Regular" } else { "Malo" }

    return @{
        Porcentaje = $salud
        Estado     = $estado
        Factores   = $factores
    }
}

# ============================================================
#  PASO 15 - SALUD DE DISCO (S.M.A.R.T.)
# ============================================================
function Verificar-SaludDisco {
    Escribir-Log "SALUD DE DISCO (S.M.A.R.T.)" -Tipo SECCION

    $discos = Get-PhysicalDisk -ErrorAction SilentlyContinue
    if (-not $discos) {
        Escribir-Log "No se pudieron obtener datos de discos fisicos." -Tipo WARN
        Agregar-Resumen "Salud de disco: no se pudieron leer datos"
        return
    }

    $hayProblemas   = $false
    $hayAdvertencias = $false

    foreach ($disco in $discos) {
        $mediaType = $disco.MediaType
        $esHDD     = $mediaType -eq "HDD"

        Escribir-Log "Disco: $($disco.FriendlyName)  |  Tipo: $mediaType  |  Tamano: $(Obtener-TamanoLegible $disco.Size)" -Tipo INFO

        # --- Estado general reportado por Windows ---
        switch ($disco.HealthStatus) {
            "Healthy"   { Escribir-Log "  Estado general      : Saludable" -Tipo OK }
            "Warning"   {
                Escribir-Log "  Estado general      : ADVERTENCIA" -Tipo WARN
                $hayAdvertencias = $true
            }
            "Unhealthy" {
                Escribir-Log "  Estado general      : NO SALUDABLE - Se recomienda reemplazo urgente" -Tipo ERROR
                $hayProblemas = $true
            }
            default     { Escribir-Log "  Estado general      : $($disco.HealthStatus)" -Tipo INFO }
        }

        Escribir-Log "  Estado operativo    : $($disco.OperationalStatus)" -Tipo INFO

        # --- Contadores S.M.A.R.T. via StorageReliabilityCounter ---
        $smart = $null
        try {
            $smart = Get-StorageReliabilityCounter -PhysicalDisk $disco -ErrorAction Stop

            # Temperatura
            if ($null -ne $smart.Temperature -and $smart.Temperature -gt 0) {
                $limiteCritico  = if ($esHDD) { 55 } else { 70 }
                $limiteWarning  = if ($esHDD) { 45 } else { 60 }
                $temp           = $smart.Temperature

                if ($temp -ge $limiteCritico) {
                    Escribir-Log "  Temperatura         : $temp C - CRITICA (limite $limiteCritico C)" -Tipo ERROR
                    $hayProblemas = $true
                } elseif ($temp -ge $limiteWarning) {
                    Escribir-Log "  Temperatura         : $temp C - ELEVADA (limite recomendado $limiteWarning C)" -Tipo WARN
                    $hayAdvertencias = $true
                } else {
                    Escribir-Log "  Temperatura         : $temp C - Normal" -Tipo OK
                }

                if ($null -ne $smart.TemperatureMax -and $smart.TemperatureMax -gt 0) {
                    Escribir-Log "  Temperatura maxima  : $($smart.TemperatureMax) C (historico)" -Tipo INFO
                }
            } else {
                Escribir-Log "  Temperatura         : No disponible" -Tipo INFO
            }

            # Desgaste (relevante en SSD/NVMe: 0 = nuevo, 100 = agotado)
            if ($null -ne $smart.Wear -and $smart.Wear -gt 0) {
                $restante = 100 - $smart.Wear
                if ($smart.Wear -ge 90) {
                    Escribir-Log "  Desgaste SSD        : $($smart.Wear)% usado ($restante% restante) - CRITICO, reemplazo urgente" -Tipo ERROR
                    $hayProblemas = $true
                } elseif ($smart.Wear -ge 70) {
                    Escribir-Log "  Desgaste SSD        : $($smart.Wear)% usado ($restante% restante) - ALTO, planifica reemplazo" -Tipo WARN
                    $hayAdvertencias = $true
                } else {
                    Escribir-Log "  Desgaste SSD        : $($smart.Wear)% usado ($restante% restante) - Normal" -Tipo OK
                }
            } else {
                if (-not $esHDD) {
                    Escribir-Log "  Desgaste SSD        : No disponible para este modelo" -Tipo INFO
                }
            }

            # Errores de lectura no corregidos (cualquier valor > 0 es critico)
            if ($null -ne $smart.ReadErrorsUncorrected -and $smart.ReadErrorsUncorrected -gt 0) {
                Escribir-Log "  Errores lectura     : $($smart.ReadErrorsUncorrected) no corregidos - FALLO INMINENTE POSIBLE" -Tipo ERROR
                $hayProblemas = $true
            } else {
                Escribir-Log "  Errores lectura     : Sin errores no corregidos" -Tipo OK
            }

            # Errores de escritura no corregidos
            if ($null -ne $smart.WriteErrorsUncorrected -and $smart.WriteErrorsUncorrected -gt 0) {
                Escribir-Log "  Errores escritura   : $($smart.WriteErrorsUncorrected) no corregidos - FALLO INMINENTE POSIBLE" -Tipo ERROR
                $hayProblemas = $true
            } else {
                Escribir-Log "  Errores escritura   : Sin errores no corregidos" -Tipo OK
            }

            # Horas de encendido (informativo)
            if ($null -ne $smart.PowerOnHours -and $smart.PowerOnHours -gt 0) {
                $anos  = [math]::Round($smart.PowerOnHours / 8760, 1)
                $nivel = if ($esHDD -and $smart.PowerOnHours -gt 35000) { " - uso prolongado, considera reemplazo preventivo" }
                         elseif (-not $esHDD -and $smart.PowerOnHours -gt 43800) { " - uso prolongado, considera reemplazo preventivo" }
                         else { "" }
                Escribir-Log "  Horas de encendido  : $($smart.PowerOnHours) h (~$anos anos)$nivel" -Tipo INFO
            }

            # Latencias maximas (alertan sobre degradacion de rendimiento)
            if ($null -ne $smart.ReadLatencyMax -and $smart.ReadLatencyMax -gt 500) {
                Escribir-Log "  Latencia max lectura: $($smart.ReadLatencyMax) ms - ELEVADA (puede indicar sectores defectuosos)" -Tipo WARN
                $hayAdvertencias = $true
            }
            if ($null -ne $smart.WriteLatencyMax -and $smart.WriteLatencyMax -gt 500) {
                Escribir-Log "  Latencia max escrit.: $($smart.WriteLatencyMax) ms - ELEVADA" -Tipo WARN
                $hayAdvertencias = $true
            }

        } catch {
            Escribir-Log "  Contadores S.M.A.R.T. no disponibles: $($_.Exception.Message)" -Tipo WARN
        }

        # Porcentaje de salud del disco
        $resultado = Calcular-PorcentajeSalud -Disco $disco -Smart $smart
        $pct    = $resultado.Porcentaje
        $barLen = 25
        $filled = [math]::Round($barLen * $pct / 100)
        $bar    = ('#' * $filled) + ('-' * ($barLen - $filled))
        $color  = if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }
        $lineaSalud = "  Salud del disco     : [$bar] $pct%  - $($resultado.Estado)"
        Write-Host $lineaSalud -ForegroundColor $color
        Add-Content -Path $Script:LogFile -Value $lineaSalud -Encoding UTF8
        if ($resultado.Factores.Count -gt 0) {
            Escribir-Log "  Factores detectados:" -Tipo INFO
            foreach ($factor in $resultado.Factores) {
                Escribir-Log "    - $factor" -Tipo INFO
            }
        }

        Escribir-Log "" -Tipo INFO
    }

    # Resumen global
    if ($hayProblemas) {
        Agregar-Resumen "Salud de disco (S.M.A.R.T.): PROBLEMAS CRITICOS DETECTADOS - revisar log y considerar reemplazo"
    } elseif ($hayAdvertencias) {
        Agregar-Resumen "Salud de disco (S.M.A.R.T.): advertencias detectadas - monitorizar de cerca"
    } else {
        Agregar-Resumen "Salud de disco (S.M.A.R.T.): todos los discos en buen estado"
    }
}

# ============================================================
#  RESUMEN FINAL
# ============================================================
function Mostrar-Resumen {
    Escribir-Log "RESUMEN DEL MANTENIMIENTO" -Tipo SECCION

    $duracion = (Get-Date) - $Script:FechaInicio
    Escribir-Log "Duracion total: $([math]::Round($duracion.TotalMinutes, 1)) minutos"
    Escribir-Log "Log completo guardado en: $Script:LogFile"
    Escribir-Log ""
    Escribir-Log "--- Resultados por area ---"

    foreach ($linea in $Script:Resumen) {
        Escribir-Log "  * $linea" -Tipo INFO
    }

    Escribir-Log ""
    Escribir-Log "Mantenimiento completado. Se recomienda reiniciar el equipo." -Tipo OK
    Escribir-Log "Consulta el log completo para revisar todos los detalles." -Tipo INFO
}

# ============================================================
#  MENU INTERACTIVO DE SELECCION DE PASOS
# ============================================================
function Mostrar-MenuPasos {
    param(
        # Array de hashtables: @{ Numero; Nombre; Desc; Funcion; Requerido; Seleccionado }
        [hashtable[]]$Definiciones
    )

    while ($true) {
        Clear-Host

        # Encabezado del menu
        Write-Host ""
        Write-Host "  $('=' * 66)" -ForegroundColor Cyan
        Write-Host "   SELECCION DE PASOS  -  Mantenimiento Windows v$Script:Version" -ForegroundColor Cyan
        Write-Host "  $('=' * 66)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ("  {0,3}  {1,-3}  {2,-40}  {3}" -f "N","Est","Paso","Descripcion") -ForegroundColor DarkGray
        Write-Host "  $('-' * 66)" -ForegroundColor DarkGray

        foreach ($paso in $Definiciones) {
            if ($paso.Requerido) {
                $estado = "[*]"
                $color  = "DarkYellow"
                $sufijo = " (requerido)"
            } elseif ($paso.Seleccionado) {
                $estado = "[X]"
                $color  = "Green"
                $sufijo = ""
            } else {
                $estado = "[ ]"
                $color  = "DarkGray"
                $sufijo = ""
            }

            Write-Host ("  {0,3}  " -f $paso.Numero) -NoNewline -ForegroundColor $color
            Write-Host ("{0,-3}  " -f $estado) -NoNewline -ForegroundColor $color
            Write-Host ("{0,-40}" -f ($paso.Nombre + $sufijo)) -NoNewline -ForegroundColor $color
            Write-Host ("  {0}" -f $paso.Desc) -ForegroundColor DarkGray
        }

        # Conteo — @() garantiza que .Count existe aunque haya 0 o 1 resultado
        $seleccionados = @($Definiciones | Where-Object { $_.Seleccionado }).Count
        Write-Host ""
        Write-Host "  $('-' * 66)" -ForegroundColor DarkGray
        Write-Host "  Pasos seleccionados: $seleccionados de $($Definiciones.Count)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Escribe el numero para activar/desactivar un paso." -ForegroundColor Yellow
        Write-Host "  Comandos: " -NoNewline -ForegroundColor Yellow
        Write-Host "[T]" -NoNewline -ForegroundColor Cyan
        Write-Host " Todos  " -NoNewline
        Write-Host "[N]" -NoNewline -ForegroundColor Cyan
        Write-Host " Ninguno  " -NoNewline
        Write-Host "[ENTER]" -NoNewline -ForegroundColor Green
        Write-Host " Ejecutar  " -NoNewline
        Write-Host "[Q]" -NoNewline -ForegroundColor Red
        Write-Host " Salir"
        Write-Host ""
        Write-Host "  > " -NoNewline -ForegroundColor Yellow
        $entrada = (Read-Host).Trim()

        switch ($entrada.ToUpper()) {
            "T" {
                $Definiciones | ForEach-Object { $_.Seleccionado = $true }
            }
            "N" {
                $Definiciones | Where-Object { -not $_.Requerido } | ForEach-Object { $_.Seleccionado = $false }
            }
            "Q" {
                Write-Host "`n  Operacion cancelada por el usuario." -ForegroundColor Red
                exit 0
            }
            "" {
                # ENTER sin texto = ejecutar con la seleccion actual
                if ($seleccionados -eq 0) {
                    Write-Host "  Debes seleccionar al menos un paso." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                } else {
                    Clear-Host
                    return
                }
            }
            default {
                $numInt = 0
                if ([int]::TryParse($entrada, [ref]$numInt)) {
                    $paso = $Definiciones | Where-Object { $_.Numero -eq $numInt } | Select-Object -First 1
                    if ($paso) {
                        if ($paso.Requerido) {
                            Write-Host "  El paso $numInt es requerido y no puede desactivarse." -ForegroundColor Red
                            Start-Sleep -Seconds 2
                        } else {
                            $paso.Seleccionado = -not $paso.Seleccionado
                        }
                    } else {
                        Write-Host "  Opcion no valida: '$entrada'" -ForegroundColor Red
                        Start-Sleep -Seconds 1
                    }
                } else {
                    Write-Host "  Opcion no valida: '$entrada'" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
        }
    }
}

# ============================================================
#  REINICIO AL FINALIZAR
# ============================================================
function Solicitar-Reinicio {
    Escribir-Log "REINICIO DEL EQUIPO" -Tipo SECCION

    if ($AutoReiniciar) {
        # Modo desatendido: cuenta regresiva cancelable con cualquier tecla
        Escribir-Log "Reinicio automatico activado. El equipo se reiniciara en $SegundosEspera segundos." -Tipo WARN
        Escribir-Log "Presiona cualquier tecla para CANCELAR el reinicio." -Tipo WARN
        Write-Host ""

        $cancelado = $false
        for ($i = $SegundosEspera; $i -gt 0; $i--) {
            Write-Host "`r  Reiniciando en $i segundo(s)... [cualquier tecla para cancelar]  " `
                -NoNewline -ForegroundColor Yellow

            # Verificar si el usuario presiono una tecla (sin bloquear)
            if ([Console]::KeyAvailable) {
                [Console]::ReadKey($true) | Out-Null
                $cancelado = $true
                break
            }
            Start-Sleep -Seconds 1
        }

        Write-Host ""

        if ($cancelado) {
            Escribir-Log "Reinicio cancelado por el usuario." -Tipo WARN
            Agregar-Resumen "Reinicio: cancelado por el usuario"
        } else {
            Escribir-Log "Iniciando reinicio del sistema..." -Tipo OK
            Agregar-Resumen "Reinicio: programado"
            Restart-Computer -Force
        }

    } else {
        # Modo interactivo: preguntar al usuario
        Write-Host ""
        Write-Host "  Se recomienda reiniciar el equipo para aplicar todos los cambios." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [S] Reiniciar ahora    [N] Reiniciar despues" -ForegroundColor White
        Write-Host ""

        $respuesta = $null
        while ($respuesta -notin @('S','N')) {
            Write-Host "  Tu eleccion (S/N): " -NoNewline -ForegroundColor Yellow
            $respuesta = ([Console]::ReadKey($true)).KeyChar.ToString().ToUpper()
            Write-Host $respuesta
        }

        if ($respuesta -eq 'S') {
            # Cuenta regresiva de 15 segundos cancelable
            Escribir-Log "El equipo se reiniciara en 15 segundos. Presiona cualquier tecla para cancelar." -Tipo WARN
            Write-Host ""

            $cancelado = $false
            for ($i = 15; $i -gt 0; $i--) {
                Write-Host "`r  Reiniciando en $i segundo(s)... [cualquier tecla para cancelar]  " `
                    -NoNewline -ForegroundColor Yellow

                if ([Console]::KeyAvailable) {
                    [Console]::ReadKey($true) | Out-Null
                    $cancelado = $true
                    break
                }
                Start-Sleep -Seconds 1
            }

            Write-Host ""

            if ($cancelado) {
                Escribir-Log "Reinicio cancelado. Puedes reiniciar manualmente cuando lo desees." -Tipo WARN
                Agregar-Resumen "Reinicio: cancelado por el usuario"
            } else {
                Escribir-Log "Iniciando reinicio del sistema..." -Tipo OK
                Agregar-Resumen "Reinicio: ejecutado"
                Restart-Computer -Force
            }
        } else {
            Escribir-Log "Reinicio pospuesto. Recuerda reiniciar el equipo manualmente." -Tipo INFO
            Agregar-Resumen "Reinicio: pospuesto  -  pendiente manual"
        }
    }
}

# ============================================================
#  PUNTO DE ENTRADA PRINCIPAL
# ============================================================
function Main {
    # Crear directorio de logs
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
    }

    # Encabezado
    Write-Host "`n$('*' * 70)" -ForegroundColor Magenta
    Write-Host "  MANTENIMIENTO COMPLETO DE WINDOWS  -  v$Script:Version" -ForegroundColor Magenta
    Write-Host "  $(Get-Date -Format 'dddd, dd/MM/yyyy HH:mm:ss')" -ForegroundColor Magenta
    Write-Host "$('*' * 70)`n" -ForegroundColor Magenta

    Escribir-Log "Inicio de mantenimiento  -  Version $Script:Version"

    # Verificar ejecucion como administrador
    $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $esAdmin) {
        Write-Host "ERROR: Este script debe ejecutarse como Administrador." -ForegroundColor Red
        Write-Host "Haz clic derecho en PowerShell y selecciona 'Ejecutar como administrador'." -ForegroundColor Yellow
        exit 1
    }

    # Verificar compatibilidad con Windows 10/11
    $build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
    if ($build -lt 10240) {
        Write-Host "ERROR: Este script requiere Windows 10 o superior." -ForegroundColor Red
        exit 1
    }

    # --- Seleccion de pasos ---

    if ($TodosLosPasos) {
        # Marcar todos como seleccionados y saltar menu
        $Script:PasosDisponibles | ForEach-Object { $_.Seleccionado = $true }
        Escribir-Log "Modo completo: se ejecutaran todos los pasos." -Tipo INFO

    } elseif ($Pasos -and $Pasos.Count -gt 0) {
        # Pre-seleccionar solo los pasos indicados por parametro
        $Script:PasosDisponibles | ForEach-Object {
            $_.Seleccionado = $_.Requerido -or ($_.Numero -in $Pasos)
        }
        $nombresSeleccionados = ($Script:PasosDisponibles |
            Where-Object { $_.Seleccionado } |
            Sort-Object Numero |
            ForEach-Object { $_.Nombre }) -join ", "
        Escribir-Log "Pasos seleccionados por parametro: $nombresSeleccionados" -Tipo INFO

    } else {
        # Mostrar menu interactivo (Seleccionado ya viene en $true desde la definicion)
        Mostrar-MenuPasos -Definiciones $Script:PasosDisponibles
    }

    # Registrar en log que pasos se ejecutaran
    $pasosActivos = @($Script:PasosDisponibles | Where-Object { $_.Seleccionado } | Sort-Object Numero).Numero
    Escribir-Log "Pasos a ejecutar: $($pasosActivos -join ', ')" -Tipo INFO

    # --- Ejecutar pasos seleccionados en orden ---
    foreach ($paso in ($Script:PasosDisponibles | Sort-Object Numero)) {
        if ($paso.Seleccionado) {
            Escribir-Log "Ejecutando paso $($paso.Numero): $($paso.Nombre)" -Tipo INFO
            try {
                & $paso.Funcion
            } catch {
                Escribir-Log "Error inesperado en paso $($paso.Numero) ($($paso.Nombre)): $($_.Exception.Message)" -Tipo ERROR
                Agregar-Resumen "Paso $($paso.Numero) ($($paso.Nombre)): ERROR  -  $($_.Exception.Message)"
            }
        } else {
            Escribir-Log "Paso $($paso.Numero) omitido por el usuario: $($paso.Nombre)" -Tipo INFO
        }
    }

    Mostrar-Resumen
    Solicitar-Reinicio
}

# Ejecutar
Main
