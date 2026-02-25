# run.ps1 - Descargador y lanzador con elevacion automatica
# Uso directo:    irm run.andresbolivar.me/run.ps1 | iex
# Con parametros: & ([scriptblock]::Create((irm 'run.andresbolivar.me/run.ps1'))) -TodosLosPasos

function Invoke-Mantenimiento {
    param(
        [switch]$AutoReiniciar,
        [int]$SegundosEspera = 60,
        [int[]]$Pasos,
        [switch]$TodosLosPasos
    )

    $ScriptUrl = 'https://raw.githubusercontent.com/audrum/mantenimiento-windows/master/Mantenimiento-Windows.ps1'
    $RunUrl    = 'https://raw.githubusercontent.com/audrum/mantenimiento-windows/master/run.ps1'

    # Verificar si la sesion actual tiene permisos de Administrador
    $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $esAdmin) {
        # Construir los argumentos para reenviarlos al proceso elevado
        $argsParts = [System.Collections.Generic.List[string]]::new()
        if ($AutoReiniciar)                                        { $argsParts.Add('-AutoReiniciar') }
        if ($PSBoundParameters.ContainsKey('SegundosEspera'))      { $argsParts.Add("-SegundosEspera $SegundosEspera") }
        if ($Pasos)                                                { $argsParts.Add("-Pasos $($Pasos -join ',')") }
        if ($TodosLosPasos)                                        { $argsParts.Add('-TodosLosPasos') }

        $argsPasados = if ($argsParts.Count -gt 0) { ' ' + ($argsParts -join ' ') } else { '' }

        # Relanzar el mismo run.ps1 en modo elevado con los parametros originales
        $cmd = "& ([scriptblock]::Create((irm '$RunUrl')))$argsPasados"
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`""
        return
    }

    # Sesion ya elevada: descargar y ejecutar el script principal
    $params = @{}
    if ($AutoReiniciar)                                        { $params['AutoReiniciar']  = $true }
    if ($PSBoundParameters.ContainsKey('SegundosEspera'))      { $params['SegundosEspera'] = $SegundosEspera }
    if ($Pasos)                                                { $params['Pasos']          = $Pasos }
    if ($TodosLosPasos)                                        { $params['TodosLosPasos']  = $true }

    $bloque = [scriptblock]::Create((Invoke-RestMethod -Uri $ScriptUrl))
    & $bloque @params
}

Invoke-Mantenimiento @args
