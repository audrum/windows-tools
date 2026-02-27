# run.ps1 - Descargador y lanzador con elevacion automatica
# Uso directo: irm run.andresbolivar.me/debloat/run.ps1 | iex

function Invoke-Debloat {

    $ScriptUrl = 'https://raw.githubusercontent.com/audrum/windows-tools/master/debloat/debloat.ps1'
    $RunUrl    = 'https://raw.githubusercontent.com/audrum/windows-tools/master/debloat/run.ps1'

    $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $esAdmin) {
        $cmd = "& ([scriptblock]::Create((irm '$RunUrl')))"
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`""
        return
    }

    try {
        $bloque = [scriptblock]::Create((Invoke-RestMethod -Uri $ScriptUrl))
    } catch {
        Write-Error "No se pudo descargar el script. Verifica tu conexion a internet. ($ScriptUrl)"
        exit 1
    }
    & $bloque
}

Invoke-Debloat
