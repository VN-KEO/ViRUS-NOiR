# ViRUS NOiR - Ultimate Cyber Defense System for Windows
# Advanced Anti-Malware, Anti-Spyware, Anti-Hacker Protection
# Version 2.0 - The King of Cyber Defense

# Requires Administrator privileges
param(
    [string]$Command = "menu"
)

# Colors for output
$Host.UI.RawUI.ForegroundColor = "White"

# Log files
$LogDir = "C:\ViRUS_NOiR\Logs"
$LogFile = "$LogDir\virus_noir.log"
$ThreatLog = "$LogDir\noir_threats.log"

# Initialize logs
function Initialize-Logs {
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp : ViRUS NOiR Started" | Out-File -FilePath $LogFile -Append
}

# Banner
function Show-Banner {
    Clear-Host
    Write-Host "    ██╗   ██╗██╗██████╗ ██╗   ██╗███████╗    ███╗   ██╗ ██████╗ ██╗██████╗ " -ForegroundColor Magenta
    Write-Host "    ██║   ██║██║██╔══██╗██║   ██║██╔════╝    ████╗  ██║██╔═══██╗██║██╔══██╗" -ForegroundColor Magenta
    Write-Host "    ██║   ██║██║██████╔╝██║   ██║███████╗    ██╔██╗ ██║██║   ██║██║██████╔╝" -ForegroundColor Magenta
    Write-Host "    ╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██║╚██╗██║██║   ██║██║██╔══██╗" -ForegroundColor Magenta
    Write-Host "     ╚████╔╝ ██║██║  ██║╚██████╔╝███████║    ██║ ╚████║╚██████╔╝██║██║  ██║" -ForegroundColor Magenta
    Write-Host "      ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝" -ForegroundColor Magenta
    Write-Host "" -ForegroundColor Magenta
    Write-Host "              ULTIMATE CYBER DEFENSE SYSTEM - THE KING OF PROTECTION" -ForegroundColor Magenta
    Write-Host "    ===================================================================" -ForegroundColor Magenta
    Write-Host ""
}

# Check Administrator privileges
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# System Hardening
function Invoke-SystemHardening {
    Write-Host "`n[ViRUS NOiR] Hardening System..." -ForegroundColor Cyan
    
    # Disable unnecessary services
    Write-Host "[*] Securing system services..." -ForegroundColor Blue
    $servicesToDisable = @("RemoteRegistry", "SSDPSRV", "upnphost", "Telnet", "TFTP", "W3SVC")
    
    foreach ($service in $servicesToDisable) {
        try {
            Stop-Service -Name $service -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  Disabled: $service" -ForegroundColor Green
        } catch {
            Write-Host "  Could not disable: $service" -ForegroundColor Yellow
        }
    }
    
    # Configure Windows Defender
    Write-Host "[*] Configuring Windows Defender..." -ForegroundColor Blue
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
        Write-Host "  Windows Defender configured" -ForegroundColor Green
    } catch {
        Write-Host "  Windows Defender configuration failed" -ForegroundColor Yellow
    }
    
    # Configure Windows Firewall
    Write-Host "[*] Configuring Windows Firewall..." -ForegroundColor Blue
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Host "  Windows Firewall configured" -ForegroundColor Green
    } catch {
        Write-Host "  Firewall configuration failed" -ForegroundColor Yellow
    }
    
    # Disable SMBv1
    Write-Host "[*] Disabling SMBv1..." -ForegroundColor Blue
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Write-Host "  SMBv1 disabled" -ForegroundColor Green
    } catch {
        Write-Host "  SMBv1 disable failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] System hardening complete" -ForegroundColor Green
}

# Advanced Firewall Configuration
function Invoke-FirewallConfiguration {
    Write-Host "`n[ViRUS NOiR] Configuring Royal Firewall..." -ForegroundColor Cyan
    
    # Block common attack ports
    Write-Host "[*] Blocking common attack vectors..." -ForegroundColor Blue
    $blockPorts = @(135, 137, 138, 139, 445, 1433, 1434, 3389, 4899, 6129)
    
    foreach ($port in $blockPorts) {
        try {
            New-NetFirewallRule -DisplayName "Block Port $port" -Direction Inbound -LocalPort $port -Protocol TCP -Action Block -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Block Port $port UDP" -Direction Inbound -LocalPort $port -Protocol UDP -Action Block -ErrorAction SilentlyContinue
        } catch {
            # Rule might already exist
        }
    }
    
    # Allow only essential outbound
    Write-Host "[*] Configuring outbound rules..." -ForegroundColor Blue
    try {
        # Allow DNS
        New-NetFirewallRule -DisplayName "Allow DNS Out" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -ErrorAction SilentlyContinue
        # Allow HTTP/HTTPS
        New-NetFirewallRule -DisplayName "Allow HTTP Out" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Allow HTTPS Out" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow -ErrorAction SilentlyContinue
    } catch {
        # Rules might already exist
    }
    
    Write-Host "[+] Royal Firewall configured" -ForegroundColor Green
}

# Malware Detection and Removal
function Invoke-MalwareHunter {
    Write-Host "`n[ViRUS NOiR] Hunting Malware and Spyware..." -ForegroundColor Cyan
    
    # Scan with Windows Defender
    Write-Host "[*] Running Windows Defender scan..." -ForegroundColor Blue
    try {
        Start-MpScan -ScanType QuickScan
        Write-Host "  Quick scan initiated" -ForegroundColor Green
    } catch {
        Write-Host "  Defender scan failed" -ForegroundColor Yellow
    }
    
    # Check for suspicious processes
    Write-Host "[*] Analyzing running processes..." -ForegroundColor Blue
    $suspiciousKeywords = @("miner", "xmrig", "cpuminer", "backdoor", "keylogger", "rat", "trojan")
    
    Get-Process | ForEach-Object {
        $process = $_
        foreach ($keyword in $suspiciousKeywords) {
            if ($process.ProcessName -like "*$keyword*" -or $process.Path -like "*$keyword*") {
                $message = "SUSPICIOUS PROCESS: $($process.ProcessName) (PID: $($process.Id))"
                Write-Host "  $message" -ForegroundColor Red
                $message | Out-File -FilePath $ThreatLog -Append
                try {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "  Terminated: $($process.ProcessName)" -ForegroundColor Green
                } catch {
                    Write-Host "  Could not terminate: $($process.ProcessName)" -ForegroundColor Yellow
                }
            }
        }
    }
    
    # Check startup programs
    Write-Host "[*] Checking startup programs..." -ForegroundColor Blue
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ForEach-Object {
        if ($_.Command -like "*curl*" -or $_.Command -like "*wget*" -or $_.Command -like "*powershell*" -or $_.Command -like "*cmd*") {
            $message = "SUSPICIOUS STARTUP: $($_.Name) - $($_.Command)"
            Write-Host "  $message" -ForegroundColor Yellow
            $message | Out-File -FilePath $ThreatLog -Append
        }
    }
    
    # Check scheduled tasks
    Write-Host "[*] Checking scheduled tasks..." -ForegroundColor Blue
    Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | ForEach-Object {
        $task = $_
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName
        if ($taskInfo -like "*curl*" -or $taskInfo -like "*wget*" -or $taskInfo -like "*powershell*") {
            $message = "SUSPICIOUS TASK: $($task.TaskName)"
            Write-Host "  $message" -ForegroundColor Yellow
            $message | Out-File -FilePath $ThreatLog -Append
        }
    }
    
    Write-Host "[+] Malware hunt completed" -ForegroundColor Green
}

# Intrusion Detection System
function Invoke-IDSDeployment {
    Write-Host "`n[ViRUS NOiR] Deploying Intrusion Detection..." -ForegroundColor Cyan
    
    # Enable auditing
    Write-Host "[*] Configuring audit policies..." -ForegroundColor Blue
    try {
        auditpol /set /category:"System" /success:enable /failure:enable
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
        auditpol /set /category:"Object Access" /success:enable /failure:enable
        auditpol /set /category:"Privilege Use" /success:enable /failure:enable
        auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
        auditpol /set /category:"Policy Change" /success:enable /failure:enable
        auditpol /set /category:"Account Management" /success:enable /failure:enable
        auditpol /set /category:"DS Access" /success:enable /failure:enable
        auditpol /set /category:"Account Logon" /success:enable /failure:enable
        Write-Host "  Audit policies configured" -ForegroundColor Green
    } catch {
        Write-Host "  Audit policy configuration failed" -ForegroundColor Yellow
    }
    
    # Configure Windows Event Log
    Write-Host "[*] Configuring event logs..." -ForegroundColor Blue
    try {
        wevtutil set-log "Microsoft-Windows-Windows Defender/Operational" /enabled:true
        wevtutil set-log "Security" /enabled:true
        wevtutil set-log "System" /enabled:true
        Write-Host "  Event logs configured" -ForegroundColor Green
    } catch {
        Write-Host "  Event log configuration failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Intrusion Detection System deployed" -ForegroundColor Green
}

# Advanced Threat Prevention
function Invoke-ThreatPrevention {
    Write-Host "`n[ViRUS NOiR] Activating Threat Prevention..." -ForegroundColor Cyan
    
    # Disable PowerShell v2
    Write-Host "[*] Disabling PowerShell v2..." -ForegroundColor Blue
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
        Write-Host "  PowerShell v2 disabled" -ForegroundColor Green
    } catch {
        Write-Host "  PowerShell v2 disable failed" -ForegroundColor Yellow
    }
    
    # Configure PowerShell execution policy
    Write-Host "[*] Configuring PowerShell execution policy..." -ForegroundColor Blue
    try {
        Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        Write-Host "  PowerShell execution policy configured" -ForegroundColor Green
    } catch {
        Write-Host "  PowerShell policy configuration failed" -ForegroundColor Yellow
    }
    
    # Enable Controlled Folder Access
    Write-Host "[*] Enabling Controlled Folder Access..." -ForegroundColor Blue
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Write-Host "  Controlled Folder Access enabled" -ForegroundColor Green
    } catch {
        Write-Host "  Controlled Folder Access enable failed" -ForegroundColor Yellow
    }
    
    # Disable AutoRun
    Write-Host "[*] Disabling AutoRun..." -ForegroundColor Blue
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue
        Write-Host "  AutoRun disabled" -ForegroundColor Green
    } catch {
        Write-Host "  AutoRun disable failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Threat prevention activated" -ForegroundColor Green
}

# Network Security
function Invoke-NetworkSecurity {
    Write-Host "`n[ViRUS NOiR] Fortifying Network..." -ForegroundColor Cyan
    
    # Configure DNS
    Write-Host "[*] Configuring secure DNS..." -ForegroundColor Blue
    try {
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @("1.1.1.1", "1.0.0.1", "9.9.9.9") -ErrorAction SilentlyContinue
        }
        Write-Host "  Secure DNS configured" -ForegroundColor Green
    } catch {
        Write-Host "  DNS configuration failed" -ForegroundColor Yellow
    }
    
    # Disable LLMNR
    Write-Host "[*] Disabling LLMNR..." -ForegroundColor Blue
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -ErrorAction SilentlyContinue
        Write-Host "  LLMNR disabled" -ForegroundColor Green
    } catch {
        Write-Host "  LLMNR disable failed" -ForegroundColor Yellow
    }
    
    # Disable NetBIOS
    Write-Host "[*] Disabling NetBIOS..." -ForegroundColor Blue
    try {
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne 2} | ForEach-Object {
            $_.SetTcpipNetbios(2)
        }
        Write-Host "  NetBIOS disabled" -ForegroundColor Green
    } catch {
        Write-Host "  NetBIOS disable failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Network fortification complete" -ForegroundColor Green
}

# Real-time Monitoring
function Start-RealtimeMonitoring {
    Write-Host "`n[ViRUS NOiR] Starting Real-time Monitoring..." -ForegroundColor Cyan
    
    # Create monitoring script
    $monitorScript = @"
    `$ThreatLog = "$ThreatLog"
    while (`$true) {
        # Monitor network connections
        Get-NetTCPConnection | Where-Object {`$_.State -eq "Established"} | ForEach-Object {
            if (`$_.RemoteAddress -like "185.*" -or `$_.RemoteAddress -like "45.*") {
                "`$(Get-Date): SUSPICIOUS CONNECTION: `$(`$_.RemoteAddress):`$(`$_.RemotePort)" | Out-File -FilePath `$ThreatLog -Append
            }
        }
        
        # Monitor high CPU processes
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | ForEach-Object {
            if (`$_.ProcessName -like "*miner*" -or `$_.ProcessName -like "*xmrig*") {
                "`$(Get-Date): CRYPTOMINER DETECTED: `$(`$_.ProcessName)" | Out-File -FilePath `$ThreatLog -Append
            }
        }
        
        Start-Sleep -Seconds 30
    }
"@
    
    $monitorScript | Out-File -FilePath "C:\ViRUS_NOiR\noir_monitor.ps1" -Force
    
    # Start monitoring job
    try {
        Start-Job -FilePath "C:\ViRUS_NOiR\noir_monitor.ps1" -Name "ViRUS_NOiR_Monitor"
        Write-Host "[+] Real-time monitoring activated" -ForegroundColor Green
    } catch {
        Write-Host "  Monitoring start failed" -ForegroundColor Yellow
    }
}

# Emergency Lockdown
function Invoke-EmergencyLockdown {
    Write-Host "`n[ViRUS NOiR] EMERGENCY LOCKDOWN ACTIVATED!" -ForegroundColor Red
    Write-Host "[!] THIS WILL DISABLE ALL NON-ESSENTIAL SERVICES" -ForegroundColor Red
    
    $confirmation = Read-Host "Are you sure you want to continue? (yes/NO)"
    if ($confirmation -ne "yes") {
        Write-Host "[*] Lockdown cancelled" -ForegroundColor Yellow
        return
    }
    
    # Block all inbound traffic
    Write-Host "[*] Blocking all inbound traffic..." -ForegroundColor Blue
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    } catch {
        Write-Host "  Firewall block failed" -ForegroundColor Yellow
    }
    
    # Stop non-essential services
    Write-Host "[*] Stopping non-essential services..." -ForegroundColor Blue
    $servicesToStop = @("Spooler", "Themes", "WSearch", "W32Time", "TabletInputService", "Fax")
    
    foreach ($service in $servicesToStop) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Write-Host "  Stopped: $service" -ForegroundColor Green
        } catch {
            Write-Host "  Could not stop: $service" -ForegroundColor Yellow
        }
    }
    
    # Disable user accounts (except current)
    Write-Host "[*] Securing user accounts..." -ForegroundColor Blue
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Get-LocalUser | Where-Object {$_.Name -ne $currentUser -and $_.Enabled} | ForEach-Object {
            Disable-LocalUser -Name $_.Name
            Write-Host "  Disabled user: $($_.Name)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  User account operations failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] System locked down" -ForegroundColor Green
}

# Security Audit
function Invoke-SecurityAudit {
    Write-Host "`n[ViRUS NOiR] Performing Security Audit..." -ForegroundColor Cyan
    
    # Check open ports
    Write-Host "[*] Scanning for open ports..." -ForegroundColor Blue
    Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
    
    # Check user accounts
    Write-Host "[*] Auditing user accounts..." -ForegroundColor Blue
    Get-LocalUser | Where-Object {$_.Enabled} | Select-Object Name, SID, LastLogon | Format-Table -AutoSize
    
    # Check local administrators
    Write-Host "[*] Checking local administrators..." -ForegroundColor Blue
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Format-Table -AutoSize
    
    # Check services
    Write-Host "[*] Checking running services..." -ForegroundColor Blue
    Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName | Format-Table -AutoSize
    
    Write-Host "[+] Security audit completed" -ForegroundColor Green
}

# Show status
function Show-Status {
    Write-Host "`n[ViRUS NOiR] System Status" -ForegroundColor Cyan
    
    # Firewall status
    $firewallStatus = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq "True"}
    if ($firewallStatus) {
        Write-Host "[+] Firewall: ACTIVE" -ForegroundColor Green
    } else {
        Write-Host "[+] Firewall: INACTIVE" -ForegroundColor Red
    }
    
    # Defender status
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus -and $defenderStatus.AntivirusEnabled) {
        Write-Host "[+] Windows Defender: ACTIVE" -ForegroundColor Green
    } else {
        Write-Host "[+] Windows Defender: INACTIVE" -ForegroundColor Red
    }
    
    # Recent threats
    if (Test-Path $ThreatLog) {
        $recentThreats = (Get-Content $ThreatLog | Select-String "SUSPICIOUS").Count
        Write-Host "[+] Recent threats detected: $recentThreats" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Recent threats detected: 0" -ForegroundColor Yellow
    }
}

# Main menu
function Show-MainMenu {
    do {
        Show-Banner
        Write-Host "1) Full System Fortification (Recommended)" -ForegroundColor Green
        Write-Host "2) Malware Hunter & Cleaner"
        Write-Host "3) Network Security Fortress"
        Write-Host "4) Intrusion Detection System"
        Write-Host "5) Real-time Threat Monitoring"
        Write-Host "6) Security Audit & Assessment"
        Write-Host "7) Emergency Lockdown"
        Write-Host "8) System Status"
        Write-Host "9) View Threat Logs"
        Write-Host "10) Exit ViRUS NOiR"
        Write-Host ""
        $choice = Read-Host "Select option [1-10]"

        switch ($choice) {
            "1" {
                Invoke-SystemHardening
                Invoke-FirewallConfiguration
                Invoke-ThreatPrevention
                Invoke-NetworkSecurity
                Invoke-IDSDeployment
            }
            "2" { Invoke-MalwareHunter }
            "3" {
                Invoke-FirewallConfiguration
                Invoke-NetworkSecurity
            }
            "4" { Invoke-IDSDeployment }
            "5" { Start-RealtimeMonitoring }
            "6" { Invoke-SecurityAudit }
            "7" { Invoke-EmergencyLockdown }
            "8" { Show-Status }
            "9" {
                if (Test-Path $ThreatLog) {
                    Write-Host "`nThreat Log:" -ForegroundColor Cyan
                    Get-Content $ThreatLog | Select-Object -Last 20
                } else {
                    Write-Host "No threat log found" -ForegroundColor Yellow
                }
            }
            "10" {
                Write-Host "[+] ViRUS NOiR - The King protects your system!" -ForegroundColor Green
                return
            }
            default { Write-Host "[!] Invalid option" -ForegroundColor Red }
        }
        
        Write-Host ""
        Read-Host "Press Enter to continue"
    } while ($true)
}

# Main execution
if (!(Test-Administrator)) {
    Write-Host "[!] ViRUS NOiR requires Administrator privileges!" -ForegroundColor Red
    Write-Host "[*] Please run PowerShell as Administrator" -ForegroundColor Yellow
    exit 1
}

Initialize-Logs

switch ($Command) {
    "status" { Show-Status }
    "scan" { Invoke-MalwareHunter }
    "audit" { Invoke-SecurityAudit }
    "monitor" { Start-RealtimeMonitoring }
    "help" {
        Show-Banner
        Write-Host "Usage: .\ViRUS_NOiR.ps1 [COMMAND]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  status    Show current protection status"
        Write-Host "  scan      Run malware scan"
        Write-Host "  audit     Perform security audit"
        Write-Host "  monitor   Start real-time monitoring"
        Write-Host "  help      Show this help message"
        Write-Host ""
        Write-Host "Without command: Start interactive menu"
    }
    default { Show-MainMenu }
}
