<#
.SYNOPSIS
    Script interactivo para eliminar bloatware de Windows 10 y 11
.DESCRIPTION
    Un script completo con menú interactivo para eliminar bloatware de forma segura, deshabilitar
    la telemetría y mejorar el rendimiento general sin romper funcionalidades críticas.
#>

# Verificar que el script se ejecuta con privilegios de Administrador
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "¡Este script necesita ejecutarse como Administrador! Por favor, abre PowerShell como Administrador e inténtalo de nuevo."
    break
}

# Definir opciones
$options = @(
    [PSCustomObject]@{ Id = 1; Name = "Deshabilitar telemetría y recopilación de datos"; Selected = $true }
    [PSCustomObject]@{ Id = 2; Name = "Deshabilitar Windows Copilot (Windows 11)"; Selected = $true }
    [PSCustomObject]@{ Id = 3; Name = "Deshabilitar Cortana (Windows 10) y búsqueda web de Bing"; Selected = $true }
    [PSCustomObject]@{ Id = 4; Name = "Deshabilitar funciones de consumidor (instalación automática de apps)"; Selected = $true }
    [PSCustomObject]@{ Id = 5; Name = "Eliminar apps UWP innecesarias (bloatware y Xbox)"; Selected = $true }
    [PSCustomObject]@{ Id = 6; Name = "Deshabilitar apps en segundo plano"; Selected = $true }
    [PSCustomObject]@{ Id = 7; Name = "Deshabilitar tareas programadas de diagnóstico"; Selected = $true }
    [PSCustomObject]@{ Id = 8; Name = "Optimizar efectos visuales (modo rendimiento)"; Selected = $false }
    [PSCustomObject]@{ Id = 9; Name = "Desinstalar OneDrive"; Selected = $false }
    [PSCustomObject]@{ Id = 10; Name = "Deshabilitar Game DVR y Xbox Game Bar"; Selected = $true }
    [PSCustomObject]@{ Id = 11; Name = "Deshabilitar historial de actividad y línea de tiempo"; Selected = $true }
    [PSCustomObject]@{ Id = 12; Name = "Desactivar consejos, trucos y sugerencias de Windows"; Selected = $true }
    [PSCustomObject]@{ Id = 13; Name = "Deshabilitar Wi-Fi Sense"; Selected = $true }
    [PSCustomObject]@{ Id = 14; Name = "Limpiar opciones del menú contextual"; Selected = $false }
)

$running = $true

while ($running) {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "         Eliminación de bloatware en Windows 10/11        " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($opt in $options) {
        $check = if ($opt.Selected) { "[X]" } else { "[ ]" }
        Write-Host "  $($opt.Id.ToString().PadLeft(2)) $check $($opt.Name)"
    }

    Write-Host ""
    Write-Host "  Escribe un número para activar/desactivar una opción."
    Write-Host "  [A] Seleccionar todo  |  [N] Deseleccionar todo  |  [R] Ejecutar selección  |  [Q] Salir"
    Write-Host ""

    $choice = Read-Host "Selecciona una opción"

    if ($choice -eq 'Q' -or $choice -eq 'q') {
        Write-Host "Saliendo sin realizar cambios." -ForegroundColor Yellow
        exit
    }
    elseif ($choice -eq 'R' -or $choice -eq 'r') {
        break # Salir del bucle y proceder a ejecutar
    }
    elseif ($choice -eq 'A' -or $choice -eq 'a') {
        foreach ($opt in $options) { $opt.Selected = $true }
    }
    elseif ($choice -eq 'N' -or $choice -eq 'n') {
        foreach ($opt in $options) { $opt.Selected = $false }
    }
    elseif ([int]::TryParse($choice, [ref]$null)) {
        $num = [int]$choice
        $match = $options | Where-Object { $_.Id -eq $num }
        if ($match) {
            $match.Selected = -not $match.Selected
        }
    }
}

Write-Host "`nRecopilando métricas de rendimiento iniciales... Por favor, espera.`n" -ForegroundColor Cyan
$driveC_before = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$beforeSpace = $driveC_before.FreeSpace
$os_before = Get-CimInstance Win32_OperatingSystem
$beforeRamFree = $os_before.FreePhysicalMemory * 1KB
$beforeProcesses = (Get-Process).Count
$beforeCpuUsage = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$beforeNetConns = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count
$removedComponents = @()

Write-Host "`nIniciando proceso de eliminación de bloatware...`n" -ForegroundColor Cyan

foreach ($opt in $options | Where-Object { $_.Selected }) {
    switch ($opt.Id) {
        1 {
            Write-Host "--> Deshabilitando telemetría y recopilación de datos..." -ForegroundColor Yellow
            $telemetryRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            if (!(Test-Path $telemetryRegPath)) { New-Item -Path $telemetryRegPath -Force | Out-Null }
            Set-ItemProperty -Path $telemetryRegPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force

            Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
            Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue

            Get-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
            Get-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue
        }
        2 {
            Write-Host "--> Deshabilitando Windows Copilot..." -ForegroundColor Yellow
            $copilotRegPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
            if (!(Test-Path $copilotRegPath)) { New-Item -Path $copilotRegPath -Force | Out-Null }
            Set-ItemProperty -Path $copilotRegPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force

            $copilotHklmRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
            if (!(Test-Path $copilotHklmRegPath)) { New-Item -Path $copilotHklmRegPath -Force | Out-Null }
            Set-ItemProperty -Path $copilotHklmRegPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force
        }
        3 {
            Write-Host "--> Deshabilitando Cortana (Windows 10) y búsqueda web en el inicio..." -ForegroundColor Yellow
            $searchRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            if (!(Test-Path $searchRegPath)) { New-Item -Path $searchRegPath -Force | Out-Null }
            Set-ItemProperty -Path $searchRegPath -Name "AllowCortana" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $searchRegPath -Name "DisableWebSearch" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $searchRegPath -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force
        }
        4 {
            Write-Host "--> Deshabilitando la instalación automática de funciones de consumidor..." -ForegroundColor Yellow
            $cloudContentRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            if (!(Test-Path $cloudContentRegPath)) { New-Item -Path $cloudContentRegPath -Force | Out-Null }
            Set-ItemProperty -Path $cloudContentRegPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
        }
        5 {
            Write-Host "--> Eliminando aplicaciones integradas innecesarias..." -ForegroundColor Yellow
            $appsToRemove = @(
                "*Microsoft.BingNews*", "*Microsoft.BingWeather*", "*Microsoft.BingFinance*", "*Microsoft.BingSports*",
                "*Microsoft.GamingApp*", "*Microsoft.GetHelp*", "*Microsoft.Getstarted*", "*Microsoft.MicrosoftOfficeHub*",
                "*Microsoft.MicrosoftSolitaireCollection*", "*Microsoft.People*", "*Microsoft.SkypeApp*",
                "*Microsoft.WindowsFeedbackHub*", "*Microsoft.WindowsMaps*", "*Microsoft.XboxApp*",
                "*Microsoft.XboxGamingOverlay*", "*Microsoft.XboxIdentityProvider*", "*Microsoft.XboxSpeechToTextOverlay*",
                "*Microsoft.ZuneMusic*", "*Microsoft.ZuneVideo*", "*Microsoft.YourPhone*", "*Microsoft.MixedReality.Portal*"
            )
            foreach ($app in $appsToRemove) {
                Write-Host "    Eliminando $app..."

                # Verificar si la app existe antes de intentar eliminarla para registrar con precisión
                $appExists = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
                if ($appExists) {
                    $removedComponents += $appExists.Name
                    $appExists | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                }

                $provAppExists = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app }
                if ($provAppExists) {
                    if ($removedComponents -notcontains $provAppExists.DisplayName) {
                        $removedComponents += $provAppExists.DisplayName
                    }
                    $provAppExists | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                }
            }
        }
        6 {
            Write-Host "--> Deshabilitando apps en segundo plano..." -ForegroundColor Yellow
            $bgAppsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
            if (!(Test-Path $bgAppsPath)) { New-Item -Path $bgAppsPath -Force | Out-Null }
            Set-ItemProperty -Path $bgAppsPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
            $bgAppsHklmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
            if (!(Test-Path $bgAppsHklmPath)) { New-Item -Path $bgAppsHklmPath -Force | Out-Null }
            Set-ItemProperty -Path $bgAppsHklmPath -Name "LetAppsRunInBackground" -Value 2 -Type DWord -Force
        }
        7 {
            Write-Host "--> Deshabilitando tareas programadas de diagnóstico..." -ForegroundColor Yellow
            $tasks = @(
                "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
                "\Microsoft\Windows\Application Experience\StartupAppTask",
                "\Microsoft\Windows\Autochk\Proxy",
                "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
                "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
            )
            foreach ($task in $tasks) {
                Disable-ScheduledTask -TaskPath "\" -TaskName $task -ErrorAction SilentlyContinue | Out-Null
                Disable-ScheduledTask -TaskName ($task -split '\\')[-1] -ErrorAction SilentlyContinue | Out-Null
            }
        }
        8 {
            Write-Host "--> Optimizando efectos visuales (modo rendimiento)..." -ForegroundColor Yellow
            $visualRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
            if (!(Test-Path $visualRegPath)) { New-Item -Path $visualRegPath -Force | Out-Null }
            Set-ItemProperty -Path $visualRegPath -Name "VisualFXSetting" -Value 2 -Type DWord -Force

            $desktopRegPath = "HKCU:\Control Panel\Desktop"
            Set-ItemProperty -Path $desktopRegPath -Name "UserPreferencesMask" -Value ([byte[]](144,18,"03",128,"10","00","00","00")) -Force

            $dwmRegPath = "HKCU:\Software\Microsoft\Windows\DWM"
            if (Test-Path $dwmRegPath) {
                Set-ItemProperty -Path $dwmRegPath -Name "EnableAeroPeek" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $dwmRegPath -Name "AlwaysHibernateThumbnails" -Value 0 -Type DWord -Force
            }
        }
        9 {
            Write-Host "--> Desinstalando OneDrive..." -ForegroundColor Yellow
            $killProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
            if ($killProcess) { Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue }

            $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
            if (!(Test-Path $oneDriveSetup)) { $oneDriveSetup = "$env:SystemRoot\System32\OneDriveSetup.exe" }

            if (Test-Path $oneDriveSetup) {
                Start-Process -FilePath $oneDriveSetup -ArgumentList "/uninstall" -Wait -NoNewWindow
            }

            # Eliminar del panel lateral del Explorador
            $nsRegPath = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
            if (Test-Path $nsRegPath) {
                Set-ItemProperty -Path $nsRegPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -Force
            }
        }
        10 {
            Write-Host "--> Deshabilitando Game DVR y Xbox Game Bar..." -ForegroundColor Yellow
            $gameDVRUser = "HKCU:\System\GameConfigStore"
            if (Test-Path $gameDVRUser) {
                Set-ItemProperty -Path $gameDVRUser -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force
            }
            $gameDVRMachine = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
            if (!(Test-Path $gameDVRMachine)) { New-Item -Path $gameDVRMachine -Force | Out-Null }
            Set-ItemProperty -Path $gameDVRMachine -Name "AllowGameDVR" -Value 0 -Type DWord -Force
        }
        11 {
            Write-Host "--> Deshabilitando historial de actividad y línea de tiempo..." -ForegroundColor Yellow
            $timelinePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            if (!(Test-Path $timelinePath)) { New-Item -Path $timelinePath -Force | Out-Null }
            Set-ItemProperty -Path $timelinePath -Name "EnableActivityFeed" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $timelinePath -Name "PublishUserActivities" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $timelinePath -Name "UploadUserActivities" -Value 0 -Type DWord -Force
        }
        12 {
            Write-Host "--> Deshabilitando consejos y sugerencias de Windows..." -ForegroundColor Yellow
            $tipsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            if (!(Test-Path $tipsPath)) { New-Item -Path $tipsPath -Force | Out-Null }
            Set-ItemProperty -Path $tipsPath -Name "DisableSoftLanding" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $tipsPath -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
        }
        13 {
            Write-Host "--> Deshabilitando Wi-Fi Sense..." -ForegroundColor Yellow
            $wifiSense = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
            if (!(Test-Path $wifiSense)) { New-Item -Path $wifiSense -Force | Out-Null }
            Set-ItemProperty -Path $wifiSense -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -Force
        }
        14 {
            Write-Host "--> Limpiando el menú contextual..." -ForegroundColor Yellow
            $contextPaths = @(
                "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing",
                "HKCR:\3DObject\shell\3D Print"
            )
            foreach ($path in $contextPaths) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

Write-Host "`nRecopilando métricas de rendimiento posteriores... Por favor, espera.`n" -ForegroundColor Cyan
Start-Sleep -Seconds 5 # Dar al sistema un momento para estabilizarse

$driveC_after = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$afterSpace = $driveC_after.FreeSpace
$spaceFreedMB = [math]::Round(($afterSpace - $beforeSpace) / 1MB, 2)

$os_after = Get-CimInstance Win32_OperatingSystem
$afterRamFree = $os_after.FreePhysicalMemory * 1KB
$ramFreedMB = [math]::Round(($afterRamFree - $beforeRamFree) / 1MB, 2)

$afterProcesses = (Get-Process).Count
$afterCpuUsage = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$afterNetConns = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count

$logDir = "C:\Debloat-Windows"
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logFile = "$logDir\debloat_log.txt"

$logContent = @"
==================================================
     Registro de rendimiento - Eliminación de bloatware
     Fecha: $(Get-Date)
==================================================

[ Almacenamiento ]
Espacio libre en C: antes : $([math]::Round($beforeSpace / 1GB, 2)) GB
Espacio libre en C: después: $([math]::Round($afterSpace / 1GB, 2)) GB
Espacio total liberado    : $spaceFreedMB MB

[ Memoria (RAM) ]
Memoria física libre antes : $([math]::Round($beforeRamFree / 1MB, 2)) MB
Memoria física libre después: $([math]::Round($afterRamFree / 1MB, 2)) MB
RAM liberada/recuperada    : $ramFreedMB MB

[ CPU y procesos ]
Procesos en ejecución antes : $beforeProcesses
Procesos en ejecución después: $afterProcesses
Carga de CPU antes         : $beforeCpuUsage %
Carga de CPU después       : $afterCpuUsage %

[ Red ]
Conexiones establecidas antes : $beforeNetConns
Conexiones establecidas después: $afterNetConns
==================================================

[ Componentes eliminados ]
$(if ($removedComponents.Count -gt 0) { $removedComponents -join "`n" } else { "No se eliminó ningún componente específico." })
==================================================
"@

$logContent | Out-File -FilePath $logFile -Encoding UTF8
Write-Host "Registro de rendimiento generado en: $logFile" -ForegroundColor Cyan

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Green
Write-Host " ¡Proceso completado! " -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""

$restartChoice = Read-Host "¿Deseas reiniciar el equipo ahora para aplicar todos los cambios? (S/N)"
if ($restartChoice -eq 'S' -or $restartChoice -eq 's') {
    Write-Host "Reiniciando el equipo en 5 segundos..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} else {
    Write-Host "Recuerda reiniciar el equipo más tarde para asegurarte de que todos los cambios surtan efecto." -ForegroundColor Yellow
}
