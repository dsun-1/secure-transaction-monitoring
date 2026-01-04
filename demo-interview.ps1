
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$startedApp = $false

function Wait-ForApp {
    param(
        [string]$Url = "http://localhost:8080",
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

function Is-DemoAppProcess {
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

Write-Host "Starting demo from: $repoRoot"

$appProcess = $null
Set-Location $repoRoot

try {
    $existingListener = Get-ListeningProcess
    if ($existingListener) {
        if (Is-DemoAppProcess $existingListener) {
            Write-Host "Step 1: Restarting app with the demo profile"
            Stop-Process -Id $existingListener.ProcessId -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        } else {
            throw "Port 8080 is already in use by another process. Stop it and retry."
        }
    }

    Write-Host "Step 1: Start the Secure Transaction Monitor (Spring Boot App)"
    $appProcess = Start-Process -FilePath "mvn" `
        -ArgumentList "-f", "ecommerce-app/pom.xml", "spring-boot:run", "-Dspring-boot.run.profiles=demo" `
        -WorkingDirectory $repoRoot `
        -PassThru -NoNewWindow
    $startedApp = $true

    if (-not (Wait-ForApp)) {
        throw "App did not start in time."
    }

    Write-Host "Step 2: Run Attack Simulation (Selenium + TestNG)"
    & mvn -f security-tests/pom.xml test -Dheadless=true -Dbrowser=chrome -DbaseUrl=http://localhost:8080

    Write-Host "Step 3: Run SIEM Threat Detection (Python)"
    & python scripts/python/security_analyzer_h2.py

    Write-Host "Step 4: Generate Incident Tickets (JIRA Integration)"
    & python scripts/python/jira_ticket_generator.py siem_incident_report.json

    Write-Host "Demo completed successfully."
} finally {
    if ($startedApp -and $appProcess -and -not $appProcess.HasExited) {
        Write-Host "Stopping app..."
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
