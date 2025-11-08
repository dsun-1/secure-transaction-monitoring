# PowerShell Security Monitoring Script
# Monitors process activity, privilege escalation attempts, and system security

param(
    [string]$OutputPath = ".\reports\security_monitoring_report.json",
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$script:SecurityEvents = @()

function Write-SecurityLog {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Verbose) {
        Write-Host $logMessage
    }
    
    Add-Content -Path ".\logs\security_monitor.log" -Value $logMessage
}

function Test-SuspiciousProcessActivity {
    Write-SecurityLog -Level "INFO" -Message "Checking for suspicious process activity..."
    
    $suspiciousProcesses = @()
    
    # Check for processes running as SYSTEM or with high privileges
    $processes = Get-Process -IncludeUserName | Where-Object {
        $_.UserName -match "SYSTEM" -or $_.PriorityClass -eq "High"
    }
    
    foreach ($proc in $processes) {
        $suspiciousProcesses += [PSCustomObject]@{
            ProcessName = $proc.ProcessName
            ProcessId = $proc.Id
            UserName = $proc.UserName
            StartTime = $proc.StartTime
            PriorityClass = $proc.PriorityClass
            WorkingSet = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        }
    }
    
    Write-SecurityLog -Level "INFO" -Message "Found $($suspiciousProcesses.Count) elevated processes"
    
    return $suspiciousProcesses
}

function Test-PrivilegeEscalation {
    Write-SecurityLog -Level "INFO" -Message "Checking for privilege escalation attempts..."
    
    $privEscalationIndicators = @()
    
    # Check recent security event logs for privilege changes
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4672, 4673, 4674  # Special privileges assigned, sensitive privilege use
        StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction SilentlyContinue | Select-Object -First 50
    
    foreach ($event in $events) {
        $privEscalationIndicators += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            EventId = $event.Id
            Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
            UserName = $event.Properties[1].Value
        }
    }
    
    Write-SecurityLog -Level "INFO" -Message "Found $($privEscalationIndicators.Count) privilege-related events"
    
    return $privEscalationIndicators
}

function Test-FailedLoginAttempts {
    Write-SecurityLog -Level "INFO" -Message "Analyzing failed login attempts..."
    
    $failedLogins = @()
    
    # Event ID 4625 = Failed login attempt
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction SilentlyContinue | Select-Object -First 100
    
    $groupedByUser = $events | Group-Object -Property {
        $_.Properties[5].Value  # Target UserName
    }
    
    foreach ($group in $groupedByUser) {
        if ($group.Count -ge 3) {  # 3 or more failed attempts
            $failedLogins += [PSCustomObject]@{
                UserName = $group.Name
                FailedAttempts = $group.Count
                FirstAttempt = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                LastAttempt = ($group.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
                Severity = if ($group.Count -ge 10) { "HIGH" } else { "MEDIUM" }
            }
        }
    }
    
    Write-SecurityLog -Level "WARNING" -Message "Found $($failedLogins.Count) accounts with multiple failed login attempts"
    
    return $failedLogins
}

function Test-UnauthorizedFileAccess {
    Write-SecurityLog -Level "INFO" -Message "Checking for unauthorized file access attempts..."
    
    $unauthorizedAccess = @()
    
    # Check for access denied events (Event ID 4656)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4656
        StartTime = (Get-Date).AddHours(-2)
    } -ErrorAction SilentlyContinue | Select-Object -First 50
    
    foreach ($event in $events) {
        $unauthorizedAccess += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            UserName = $event.Properties[1].Value
            ObjectName = $event.Properties[6].Value
            AccessMask = $event.Properties[9].Value
        }
    }
    
    Write-SecurityLog -Level "INFO" -Message "Found $($unauthorizedAccess.Count) unauthorized access attempts"
    
    return $unauthorizedAccess
}

function Test-NetworkConnections {
    Write-SecurityLog -Level "INFO" -Message "Analyzing suspicious network connections..."
    
    $suspiciousConnections = @()
    
    # Get established connections to non-standard ports
    $connections = Get-NetTCPConnection -State Established | Where-Object {
        $_.RemotePort -notin @(80, 443, 8080, 8443) -and
        $_.RemoteAddress -notlike "127.*" -and
        $_.RemoteAddress -notlike "::1"
    }
    
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        
        $suspiciousConnections += [PSCustomObject]@{
            LocalAddress = $conn.LocalAddress
            LocalPort = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            State = $conn.State
            ProcessName = $process.ProcessName
            ProcessId = $conn.OwningProcess
        }
    }
    
    Write-SecurityLog -Level "INFO" -Message "Found $($suspiciousConnections.Count) connections to non-standard ports"
    
    return $suspiciousConnections
}

function Get-OpenPorts {
    Write-SecurityLog -Level "INFO" -Message "Scanning for open listening ports..."
    
    $listeningPorts = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, State
    
    $portsWithProcess = $listeningPorts | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            ProcessName = $process.ProcessName
            ProcessId = $_.OwningProcess
        }
    }
    
    Write-SecurityLog -Level "INFO" -Message "Found $($portsWithProcess.Count) listening ports"
    
    return $portsWithProcess
}

# Main Execution
Write-Host "=" * 80
Write-Host "PowerShell Security Monitoring Script"
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "=" * 80

# Create necessary directories
New-Item -ItemType Directory -Force -Path ".\reports" | Out-Null
New-Item -ItemType Directory -Force -Path ".\logs" | Out-Null

# Run all security checks
$report = @{
    GeneratedAt = (Get-Date).ToString("o")
    Hostname = $env:COMPUTERNAME
    SuspiciousProcesses = Test-SuspiciousProcessActivity
    PrivilegeEscalation = Test-PrivilegeEscalation
    FailedLoginAttempts = Test-FailedLoginAttempts
    UnauthorizedAccess = Test-UnauthorizedFileAccess
    SuspiciousConnections = Test-NetworkConnections
    OpenPorts = Get-OpenPorts
}

# Calculate summary
$summary = @{
    TotalSuspiciousProcesses = $report.SuspiciousProcesses.Count
    TotalPrivilegeEvents = $report.PrivilegeEscalation.Count
    TotalFailedLogins = $report.FailedLoginAttempts.Count
    TotalUnauthorizedAccess = $report.UnauthorizedAccess.Count
    TotalSuspiciousConnections = $report.SuspiciousConnections.Count
    TotalOpenPorts = $report.OpenPorts.Count
}

$report.Summary = $summary

# Save report
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "`n" + "=" * 80
Write-Host "Security Monitoring Summary:"
Write-Host "  Suspicious Processes: $($summary.TotalSuspiciousProcesses)"
Write-Host "  Privilege Events: $($summary.TotalPrivilegeEvents)"
Write-Host "  Failed Login Attempts: $($summary.TotalFailedLogins)"
Write-Host "  Unauthorized Access: $($summary.TotalUnauthorizedAccess)"
Write-Host "  Suspicious Connections: $($summary.TotalSuspiciousConnections)"
Write-Host "  Open Listening Ports: $($summary.TotalOpenPorts)"
Write-Host "=" * 80
Write-Host "`nReport saved to: $OutputPath"

# Exit with appropriate code
if ($summary.TotalFailedLogins -ge 5 -or $summary.TotalUnauthorizedAccess -ge 3) {
    Write-SecurityLog -Level "ERROR" -Message "High-risk security events detected"
    exit 1
} else {
    Write-SecurityLog -Level "INFO" -Message "Security monitoring completed successfully"
    exit 0
}
