$ErrorActionPreference = 'Stop'
$ManagerArgs = @($args)
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvRoot = Join-Path $Root '.orchestrator-cookie\venv'
$VenvPython = Join-Path $VenvRoot 'Scripts\python.exe'
$Installer = Join-Path $Root 'scripts\installer.py'

function Get-PythonVersion {
    param([string]$CommandPath, [string[]]$PrefixArgs = @())
    try {
        $value = & $CommandPath @PrefixArgs -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>$null
        if ($LASTEXITCODE -ne 0) { return 'unavailable' }
        return ([string]$value).Trim()
    } catch {
        return 'unavailable'
    }
}

function Test-SupportedPython {
    param([string]$Version)
    return $Version -match '^3\.(11|12|13)\.\d+$'
}

function Resolve-CommandPath {
    param([string]$Name)
    $resolved = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $resolved) { return $null }
    return $resolved.Source
}

function Resolve-ExplicitPython {
    $override = $env:ORCHESTRATOR_PYTHON
    $containsSeparator = $override.Contains('\') -or $override.Contains('/')
    if ($containsSeparator -and -not [System.IO.Path]::IsPathRooted($override)) {
        Write-Error 'BLOCKED: ORCHESTRATOR_PYTHON must be an absolute path or command name.'
        exit 3
    }
    if ([System.IO.Path]::IsPathRooted($override)) {
        $path = $override
    } else {
        $path = Resolve-CommandPath $override
    }
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Error "BLOCKED: ORCHESTRATOR_PYTHON '$override' is unavailable or not executable."
        exit 3
    }
    $version = Get-PythonVersion $path
    if (-not (Test-SupportedPython $version)) {
        Write-Error "BLOCKED: ORCHESTRATOR_PYTHON resolved to Python $version; Python 3.11, 3.12, or 3.13 is required."
        exit 3
    }
    return [pscustomobject]@{ Path = $path; Prefix = @(); Label = 'ORCHESTRATOR_PYTHON'; Version = $version }
}

function Resolve-SystemPython {
    $candidates = @()
    foreach ($name in @('python3.13', 'python3.12', 'python3.11')) {
        $path = Resolve-CommandPath $name
        if ($path) { $candidates += [pscustomobject]@{ Path = $path; Prefix = @(); Label = $name } }
    }
    $launcher = Resolve-CommandPath 'py'
    if ($launcher) {
        foreach ($minor in @('3.13', '3.12', '3.11')) {
            $candidates += [pscustomobject]@{ Path = $launcher; Prefix = @("-$minor"); Label = "py -$minor" }
        }
    }
    foreach ($name in @('python.exe', 'python', 'python3')) {
        $path = Resolve-CommandPath $name
        if ($path) { $candidates += [pscustomobject]@{ Path = $path; Prefix = @(); Label = $name } }
    }
    $discovered = @()
    foreach ($candidate in $candidates) {
        $version = Get-PythonVersion $candidate.Path $candidate.Prefix
        if (Test-SupportedPython $version) {
            $candidate | Add-Member -NotePropertyName Version -NotePropertyValue $version
            return $candidate
        }
        $discovered += "$($candidate.Label): Python $version"
    }
    $detail = if ($discovered.Count) { ' Discovered ' + ($discovered -join '; ') + '.' } else { '' }
    Write-Error "BLOCKED: Python 3.11, 3.12, or 3.13 is required.$detail"
    Write-Error 'REMEDIATION: install an approved Python 3.13 package (for example: winget install -e --id Python.Python.3.13), set ORCHESTRATOR_PYTHON to python.exe if needed, and rerun .\install.ps1 init. This installer will not install it.'
    exit 3
}

function Invoke-Manager {
    param($Candidate)
    $env:ORCHESTRATOR_RESOLVED_PYTHON = $Candidate.Path
    & $Candidate.Path @($Candidate.Prefix) $Installer @ManagerArgs
    exit $LASTEXITCODE
}

$ExplicitPython = $null
if ($env:ORCHESTRATOR_PYTHON) {
    $ExplicitPython = Resolve-ExplicitPython
}

if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
    $managedVersion = Get-PythonVersion $VenvPython
    if (Test-SupportedPython $managedVersion) {
        if ($null -ne $ExplicitPython -and $ManagerArgs.Count -gt 0 -and $ManagerArgs[0] -eq 'init') {
            Invoke-Manager $ExplicitPython
        }
        Invoke-Manager ([pscustomobject]@{ Path = $VenvPython; Prefix = @(); Version = $managedVersion })
    }
    if ($ManagerArgs.Count -eq 0 -or $ManagerArgs[0] -ne 'init') {
        Write-Error "BLOCKED: the managed environment exists but its Python $managedVersion is unusable; run install init to repair it."
        exit 3
    }
    Write-Warning "REPAIR: managed Python $managedVersion is unsupported; selecting a supported system Python for this clone-local repair."
} elseif (Test-Path -LiteralPath $VenvRoot -PathType Container) {
    if ($ManagerArgs.Count -eq 0 -or $ManagerArgs[0] -ne 'init') {
        Write-Error 'BLOCKED: the managed environment exists but its Python is unusable; run install init to repair it.'
        exit 3
    }
    Write-Warning 'REPAIR: managed Python is unusable; using system Python only to repair this clone-local environment.'
}

$selected = if ($null -ne $ExplicitPython) { $ExplicitPython } else { Resolve-SystemPython }
Invoke-Manager $selected
