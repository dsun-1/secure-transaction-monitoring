
param(
    [string]$DemoProfile = "demo",
    [string]$BaseUrl = "http://localhost:8080",
    [string]$Browser = "chrome",
    [bool]$Headless = $false,
    [bool]$InstallPythonDependencies = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Fixed PowerShell function naming to use approved verbs

$repoRoot = $PSScriptRoot
$startedApp = $false
$lockFile = Join-Path $repoRoot "data\security-events.lock.db"

function Wait-ForApp {
    param(
        [string]$Url = $BaseUrl,
        [int]$Attempts = 40,
        [int]$DelaySeconds = 2
    )

    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 | Out-Null
            Write-Host "App is up at $Url"
            return $true
        } catch {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    return $false
}

function Get-ListeningProcess {
    $conn = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $conn) {
        return $null
    }

    return Get-CimInstance Win32_Process -Filter "ProcessId=$($conn.OwningProcess)"
}

function Confirm-DemoAppProcess {
    param(
        [object]$ProcessInfo
    )

    if (-not $ProcessInfo) {
        return $false
    }

    $cmd = $ProcessInfo.CommandLine
    return $cmd -like "*spring-boot:run*" `
        -or $cmd -like "*com.security.ecommerce.EcommerceApplication*" `
        -or $cmd -like "*secure-transac\\ecommerce-app*"
}

function Install-PythonDependencies {
    param(
        [string]$Requirements = "scripts/python/requirements.txt"
    )

    if (-not (Test-Path $Requirements)) {
        Write-Host "Python requirements file not found at $Requirements, skipping installation."
        return
    }

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        throw "Python is not installed or not available in PATH."
    }

    Write-Host "Installing Python dependencies from $Requirements"
    & python -m pip install --upgrade pip
    & python -m pip install -r $Requirements
}

Write-Host "Starting demo from: $repoRoot"

$appProcess = $null
Set-Location $repoRoot

try {
    $existingListener = Get-ListeningProcess
    if ($existingListener) {
        if (Confirm-DemoAppProcess $existingListener) {
            Write-Host "Step 1: Restarting app with the demo profile"
            Stop-Process -Id $existingListener.ProcessId -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } else {
            throw "Port 8080 is already in use by another process. Stop it and retry."
        }
    }

    if ((-not $existingListener) -and (Test-Path $lockFile)) {
        Write-Host "Cleaning stale H2 lock file: $lockFile"
        Remove-Item -Force $lockFile -ErrorAction SilentlyContinue
    }

    Write-Host "Step 1: Start the Secure Transaction Monitor (Spring Boot App)"
    $appProcess = Start-Process -FilePath "mvn" `
        -ArgumentList "-f", "ecommerce-app/pom.xml", "spring-boot:run", "-Dspring-boot.run.profiles=$DemoProfile" `
        -WorkingDirectory $repoRoot `
        -PassThru -NoNewWindow
    $startedApp = $true

    if (-not (Wait-ForApp -Url $BaseUrl)) {
        throw "App did not start in time."
    }

    Write-Host "Step 2: Run Attack Simulation (Selenium + TestNG)"
    $headlessFlag = if ($Headless) { "true" } else { "false" }
    Write-Host "Running attack simulation with:"
    Write-Host "  baseUrl = $BaseUrl"
    Write-Host "  browser = $Browser"
    Write-Host "  headless = $headlessFlag"
    try {
        & mvn -f security-tests/pom.xml test `
            "-Dheadless=$headlessFlag" `
            "-Dbrowser=$Browser" `
            "-DbaseUrl=$BaseUrl"
    } catch {
        Write-Warning "Attack simulation failed; continuing to SIEM/JIRA steps."
    }

    Write-Host "Step 3: Run SIEM Threat Detection (Python)"
    if ($InstallPythonDependencies) {
        Install-PythonDependencies -Requirements "scripts/python/requirements.txt"
    }
    & python scripts/python/security_analyzer_h2.py
    Write-Host "Step 3 complete: SIEM report generated."

    Write-Host "Step 4: Generate Incident Tickets (JIRA Integration)"
    & python scripts/python/jira_ticket_generator.py siem_incident_report.json
    Write-Host "Step 4 complete: JIRA ticket generation finished."

    Write-Host "Demo completed successfully."
} finally {
    if ($startedApp -and $appProcess -and -not $appProcess.HasExited) {
        Write-Host "Stopping app..."
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
