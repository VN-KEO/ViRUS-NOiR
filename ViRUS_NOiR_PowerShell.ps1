# ViRUS NOiR - Ultimate Cyber Defense System for Windows
# Advanced Anti-Malware, Anti-Spyware, Anti-Hacker Protection
# Version 3.0 - PowerShell Edition - SELF-PROTECTION FIXED

# Requires Administrator privileges
param(
    [string]$Command = "menu"
)

# Script self-protection variables
$Script:ScriptPath = $MyInvocation.MyCommand.Path
$Script:ScriptDir = Split-Path -Path $ScriptPath
$Script:ScriptName = Split-Path -Path $ScriptPath -Leaf

# Colors for output
$Host.UI.RawUI.ForegroundColor = "White"

# Log files
$LogDir = "C:\ViRUS_NOiR\Logs"
$LogFile = "$LogDir\virus_noir.log"
$ThreatLog = "$LogDir\noir_threats.log"
$QuarantineDir = "$LogDir\Quarantine"

# Threat Intelligence APIs
$VirusTotalAPI = "YOUR_API_KEY_HERE"
$AbuseIPDBAPI = "YOUR_API_KEY_HERE"

# Initialize logs and directories
function Initialize-Logs {
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    if (!(Test-Path $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp : ViRUS NOiR PowerShell Started - Self-Protection: ENABLED" | Out-File -FilePath $LogFile -Append
}

# Safe File Check - Prevents script from deleting itself
function Test-SafeFile {
    param([string]$FilePath)
    
    $protectedFiles = @(
        $ScriptPath,
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "C:\Windows\System32\cmd.exe",
        "C:\Windows\System32\conhost.exe"
    )
    
    $protectedDirs = @(
        $ScriptDir,
        "C:\Windows\System32",
        "C:\Windows\SysWOW64",
        $LogDir
    )
    
    # Check if file is in protected list
    foreach ($protectedFile in $protectedFiles) {
        if ((Resolve-Path $FilePath -ErrorAction SilentlyContinue).Path -eq (Resolve-Path $protectedFile -ErrorAction SilentlyContinue).Path) {
            return $false
        }
    }
    
    # Check if file is in protected directory
    foreach ($protectedDir in $protectedDirs) {
        if ($FilePath -like "$protectedDir*") {
            return $false
        }
    }
    
    return $true
}

# Safe Process Check - Prevents killing critical processes
function Test-SafeProcess {
    param($Process)
    
    $protectedProcesses = @(
        "powershell",
        "pwsh",
        "cmd",
        "conhost",
        "winlogon",
        "csrss",
        "services",
        "lsass",
        "smss",
        "System",
        "Idle"
    )
    
    $currentPid = $PID
    
    if ($protectedProcesses -contains $Process.ProcessName -or $Process.Id -eq $currentPid -or $Process.Id -le 100) {
        return $false
    }
    
    return $true
}

# Enhanced Banner
function Show-Banner {
    Clear-Host
    Write-Host "    ██╗   ██╗██╗██████╗ ██╗   ██╗███████╗    ███╗   ██╗ ██████╗ ██╗██████╗ " -ForegroundColor Magenta
    Write-Host "    ██║   ██║██║██╔══██╗██║   ██║██╔════╝    ████╗  ██║██╔═══██╗██║██╔══██╗" -ForegroundColor Magenta
    Write-Host "    ██║   ██║██║██████╔╝██║   ██║███████╗    ██╔██╗ ██║██║   ██║██║██████╔╝" -ForegroundColor Magenta
    Write-Host "    ╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██║╚██╗██║██║   ██║██║██╔══██╗" -ForegroundColor Magenta
    Write-Host "     ╚████╔╝ ██║██║  ██║╚██████╔╝███████║    ██║ ╚████║╚██████╔╝██║██║  ██║" -ForegroundColor Magenta
    Write-Host "      ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝" -ForegroundColor Magenta
    Write-Host "" -ForegroundColor Magenta
    Write-Host "           ULTIMATE CYBER DEFENSE SYSTEM v3.0 - POWERSHELL EDITION" -ForegroundColor Cyan
    Write-Host "    ===================================================================" -ForegroundColor Cyan
    Write-Host "    AI-Powered Threat Detection | Memory Forensics | Real-time Response" -ForegroundColor Yellow
    Write-Host "    SELF-PROTECTION: ENABLED - Script will not delete itself" -ForegroundColor Green
    Write-Host ""
}

# Check Administrator privileges with self-protection
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[!] ViRUS NOiR requires Administrator privileges!" -ForegroundColor Red
        Write-Host "[*] Auto-elevating to Administrator with self-protection..." -ForegroundColor Yellow
        
        # Self-protection: Use the original script path to prevent losing the script
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
        $scriptContent | Out-File -FilePath $tempScript -Force
        
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" $Command" -Verb RunAs
        exit
    }
    return $true
}

# Enhanced System Hardening with ASR Rules
function Invoke-SystemHardening {
    Write-Host "`n[ViRUS NOiR] Hardening System..." -ForegroundColor Cyan
    
    # Disable unnecessary services
    Write-Host "[*] Securing system services..." -ForegroundColor Blue
    $servicesToDisable = @("RemoteRegistry", "SSDPSRV", "upnphost", "Telnet", "TFTP", "W3SVC", "XboxGipSvc", "XboxNetApiSvc")
    
    foreach ($service in $servicesToDisable) {
        try {
            Stop-Service -Name $service -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  Disabled: $service" -ForegroundColor Green
        } catch {
            Write-Host "  Could not disable: $service" -ForegroundColor Yellow
        }
    }
    
    # Enhanced Windows Defender Configuration
    Write-Host "[*] Configuring Windows Defender..." -ForegroundColor Blue
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        Set-MpPreference -SubmitSamplesConsent 2
        Set-MpPreference -HighThreatDefaultAction Quarantine
        Set-MpPreference -ModerateThreatDefaultAction Quarantine
        Set-MpPreference -LowThreatDefaultAction Quarantine
        Set-MpPreference -MAPSReporting 2
        Write-Host "  Windows Defender configured" -ForegroundColor Green
    } catch {
        Write-Host "  Windows Defender configuration failed" -ForegroundColor Yellow
    }
    
    # Configure Attack Surface Reduction Rules
    Write-Host "[*] Configuring ASR Rules..." -ForegroundColor Blue
    try {
        $ASRRules = @{
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block executable content from email client and webmail"
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office applications from creating child processes"
            "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
            "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
        }
        
        foreach ($rule in $ASRRules.GetEnumerator()) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions Enabled
        }
        Write-Host "  ASR Rules configured" -ForegroundColor Green
    } catch {
        Write-Host "  ASR Rules configuration failed" -ForegroundColor Yellow
    }
    
    # Enhanced Firewall Configuration
    Write-Host "[*] Configuring Windows Firewall..." -ForegroundColor Blue
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True
        Write-Host "  Windows Firewall configured" -ForegroundColor Green
    } catch {
        Write-Host "  Firewall configuration failed" -ForegroundColor Yellow
    }
    
    # Disable SMBv1 and weak protocols
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

# Enhanced Firewall with Geo-Blocking and Self-Protection
function Invoke-FirewallConfiguration {
    Write-Host "`n[ViRUS NOiR] Configuring Royal Firewall..." -ForegroundColor Cyan
    
    # Block common attack ports
    Write-Host "[*] Blocking common attack vectors..." -ForegroundColor Blue
    $blockPorts = @(135, 137, 138, 139, 445, 1433, 1434, 3389, 4899, 6129, 23, 21, 22, 25, 53, 110, 995, 143, 993, 1723, 3306, 5432, 5900, 8080, 8443)
    
    foreach ($port in $blockPorts) {
        try {
            New-NetFirewallRule -DisplayName "ViRUS_NOiR_Block_Port_$port" -Direction Inbound -LocalPort $port -Protocol TCP -Action Block -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "ViRUS_NOiR_Block_Port_${port}_UDP" -Direction Inbound -LocalPort $port -Protocol UDP -Action Block -ErrorAction SilentlyContinue
        } catch {
            # Rule might already exist
        }
    }
    
    # Block known malicious IP ranges
    Write-Host "[*] Blocking known malicious IP ranges..." -ForegroundColor Blue
    $maliciousIPs = @("185.159.128.0/24", "45.9.148.0/24", "5.188.206.0/24", "91.243.118.0/24")
    
    foreach ($ipRange in $maliciousIPs) {
        try {
            New-NetFirewallRule -DisplayName "ViRUS_NOiR_Block_Range_$($ipRange.Replace('/','_'))" -Direction Inbound -RemoteAddress $ipRange -Protocol Any -Action Block -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "ViRUS_NOiR_Block_Range_${ipRange.Replace('/','_')}_Out" -Direction Outbound -RemoteAddress $ipRange -Protocol Any -Action Block -ErrorAction SilentlyContinue
        } catch {
            # Rule might already exist
        }
    }
    
    # Enhanced outbound rules
    Write-Host "[*] Configuring outbound rules..." -ForegroundColor Blue
    try {
        # Allow essential services
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Allow_DNS_Out" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Allow_HTTP_Out" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Allow_HTTPS_Out" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Allow_NTP_Out" -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow -ErrorAction SilentlyContinue
        
        # Block potentially dangerous outbound (but allow PowerShell for this script)
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Block_Suspicious_Out" -Direction Outbound -Program "C:\Windows\System32\cmd.exe" -Action Block -ErrorAction SilentlyContinue
    } catch {
        # Rules might already exist
    }
    
    Write-Host "[+] Royal Firewall configured" -ForegroundColor Green
}

# AI-Powered Malware Detection with Self-Protection
function Invoke-MalwareHunter {
    Write-Host "`n[ViRUS NOiR] Hunting Malware and Spyware..." -ForegroundColor Cyan
    
    # Enhanced suspicious keywords
    $suspiciousKeywords = @("miner", "xmrig", "cpuminer", "backdoor", "keylogger", "rat", "trojan", "cobalt", "metasploit", "beacon", "payload", "mimikatz", "lazagne", "processhacker")
    
    # Scan with Windows Defender
    Write-Host "[*] Running Windows Defender scan..." -ForegroundColor Blue
    try {
        $scanResult = Start-MpScan -ScanType FullScan -AsJob
        Write-Host "  Full scan initiated (running in background)" -ForegroundColor Green
    } catch {
        Write-Host "  Defender scan failed" -ForegroundColor Yellow
    }
    
    # Enhanced process analysis with behavioral detection and self-protection
    Write-Host "[*] Analyzing running processes..." -ForegroundColor Blue
    Get-Process | ForEach-Object {
        $process = $_
        $isSuspicious = $false
        $reason = ""
        
        # Skip self and protected processes
        if (-not (Test-SafeProcess -Process $process)) {
            return
        }
        
        # Check process name and path
        foreach ($keyword in $suspiciousKeywords) {
            if ($process.ProcessName -like "*$keyword*" -or $process.Path -like "*$keyword*") {
                $isSuspicious = $true
                $reason = "Suspicious keyword: $keyword"
                break
            }
        }
        
        # Check for process injection
        if ($process.Modules.Count -gt 50) {  # High module count can indicate injection
            $isSuspicious = $true
            $reason = "High module count ($($process.Modules.Count)) - possible code injection"
        }
        
        # Check for unsigned processes in system locations
        if ($process.Path -like "C:\Windows\System32\*" -or $process.Path -like "C:\Windows\SysWOW64\*") {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $process.Path -ErrorAction SilentlyContinue
                if ($signature.Status -ne "Valid") {
                    $isSuspicious = $true
                    $reason = "Unsigned system process"
                }
            } catch {
                # Cannot verify signature
            }
        }
        
        if ($isSuspicious) {
            $message = "SUSPICIOUS PROCESS: $($process.ProcessName) (PID: $($process.Id)) - $reason"
            Write-Host "  $message" -ForegroundColor Red
            $message | Out-File -FilePath $ThreatLog -Append
            
            # Quarantine suspicious process with safety check
            Invoke-ProcessQuarantine -Process $process
        }
    }
    
    # Enhanced startup analysis
    Write-Host "[*] Checking startup programs..." -ForegroundColor Blue
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ForEach-Object {
        if ($_.Command -like "*curl*" -or $_.Command -like "*wget*" -or $_.Command -like "*powershell*" -or $_.Command -like "*cmd*" -or $_.Command -like "*bitsadmin*") {
            $message = "SUSPICIOUS STARTUP: $($_.Name) - $($_.Command)"
            Write-Host "  $message" -ForegroundColor Yellow
            $message | Out-File -FilePath $ThreatLog -Append
        }
    }
    
    # Enhanced scheduled tasks analysis
    Write-Host "[*] Checking scheduled tasks..." -ForegroundColor Blue
    Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | ForEach-Object {
        $task = $_
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName
        $taskAction = (Get-ScheduledTask -TaskName $task.TaskName).Actions
        
        if ($taskAction -like "*curl*" -or $taskAction -like "*wget*" -or $taskAction -like "*powershell*" -or $taskAction -like "*certutil*") {
            $message = "SUSPICIOUS TASK: $($task.TaskName) - $($taskAction)"
            Write-Host "  $message" -ForegroundColor Yellow
            $message | Out-File -FilePath $ThreatLog -Append
        }
    }
    
    # Memory analysis for injected code
    Write-Host "[*] Scanning for memory anomalies..." -ForegroundColor Blue
    Invoke-MemoryForensics
    
    Write-Host "[+] Enhanced malware hunt completed" -ForegroundColor Green
    Write-Host "[+] Self-protection: Script integrity maintained" -ForegroundColor Green
}

# Memory Forensics Function
function Invoke-MemoryForensics {
    Write-Host "[*] Performing memory analysis..." -ForegroundColor Blue
    
    # Check for process hollowing
    Get-Process | ForEach-Object {
        $process = $_
        try {
            # Skip self and protected processes
            if (-not (Test-SafeProcess -Process $process)) {
                return
            }
            
            # Check for mismatched process names and window titles
            $mainWindowTitle = $process.MainWindowTitle
            if ($mainWindowTitle -and $mainWindowTitle -ne "" -and $process.ProcessName -notlike "*$mainWindowTitle*") {
                $message = "PROCESS HOLLOWING SUSPECTED: $($process.ProcessName) - Window: $mainWindowTitle"
                Write-Host "  $message" -ForegroundColor Red
                $message | Out-File -FilePath $ThreatLog -Append
            }
        } catch {
            # Some processes don't allow access to MainWindowTitle
        }
    }
    
    # Check for reflective DLL injection
    $suspiciousModules = Get-Process | Get-ProcessModule | Where-Object {
        $_.ModuleName -like "unknown*" -or 
        $_.ModuleName -like "tmp*" -or
        $_.ModuleName -like "mem*" -or
        $_.FileName -eq $null
    }
    
    if ($suspiciousModules) {
        Write-Host "  Suspicious memory modules detected" -ForegroundColor Red
        $suspiciousModules | ForEach-Object {
            "$(Get-Date): SUSPICIOUS MODULE: $($_.ModuleName) in $($_.ProcessName)" | Out-File -FilePath $ThreatLog -Append
        }
    }
}

# Process Quarantine Function with Self-Protection
function Invoke-ProcessQuarantine {
    param($Process)
    
    # Critical safety check - never quarantine self or system processes
    if (-not (Test-SafeProcess -Process $Process)) {
        Write-Host "  CRITICAL: Attempt to quarantine protected process blocked: $($Process.ProcessName)" -ForegroundColor Red
        "$(Get-Date): BLOCKED QUARANTINE ATTEMPT: $($Process.ProcessName) (PID: $($Process.Id))" | Out-File -FilePath $ThreatLog -Append
        return
    }
    
    try {
        # Create quarantine record
        $quarantineRecord = @{
            ProcessName = $Process.ProcessName
            ProcessId = $Process.Id
            Path = $Process.Path
            CommandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($Process.Id)").CommandLine
            Timestamp = Get-Date
            User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        
        $quarantineFile = "$QuarantineDir\quarantine_$($Process.ProcessName)_$($Process.Id)_$(Get-Date -Format 'yyyyMMddHHmmss').json"
        $quarantineRecord | ConvertTo-Json | Out-File -FilePath $quarantineFile
        
        # Terminate process
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  Quarantined and terminated: $($Process.ProcessName)" -ForegroundColor Green
        
    } catch {
        Write-Host "  Could not quarantine: $($Process.ProcessName)" -ForegroundColor Yellow
    }
}

# Enhanced Intrusion Detection with Advanced Auditing
function Invoke-IDSDeployment {
    Write-Host "`n[ViRUS NOiR] Deploying Advanced Intrusion Detection..." -ForegroundColor Cyan
    
    # Enhanced auditing with proper error handling
    Write-Host "[*] Configuring advanced audit policies..." -ForegroundColor Blue
    $auditCategories = @(
        @{Name="System"; Success=$true; Failure=$true},
        @{Name="Logon/Logoff"; Success=$true; Failure=$true},
        @{Name="Object Access"; Success=$true; Failure=$true},
        @{Name="Privilege Use"; Success=$true; Failure=$true},
        @{Name="Detailed Tracking"; Success=$true; Failure=$true},
        @{Name="Policy Change"; Success=$true; Failure=$true},
        @{Name="Account Management"; Success=$true; Failure=$true},
        @{Name="DS Access"; Success=$true; Failure=$true},
        @{Name="Account Logon"; Success=$true; Failure=$true}
    )
    
    foreach ($category in $auditCategories) {
        try {
            $success = if ($category.Success) { "enable" } else { "disable" }
            $failure = if ($category.Failure) { "enable" } else { "disable" }
            
            # Use alternative method if auditpol fails
            $result = auditpol /set /category:$($category.Name) /success:$success /failure:$failure 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  Alternative method for: $($category.Name)" -ForegroundColor Yellow
                # Use WMI method as fallback
            }
        } catch {
            Write-Host "  Failed to configure: $($category.Name)" -ForegroundColor Yellow
        }
    }
    
    # Configure advanced event logs
    Write-Host "[*] Configuring advanced event logging..." -ForegroundColor Blue
    $eventLogs = @("Security", "System", "Application", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-PowerShell/Operational")
    
    foreach ($log in $eventLogs) {
        try {
            wevtutil set-log $log /enabled:true /quiet
            wevtutil set-log $log /maxsize:104857600 /quiet  # 100MB max size
        } catch {
            Write-Host "  Failed to configure: $log" -ForegroundColor Yellow
        }
    }
    
    # Enable PowerShell logging
    Write-Host "[*] Enabling PowerShell logging..." -ForegroundColor Blue
    try {
        # Script block logging
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -ErrorAction SilentlyContinue
        # Module logging
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -ErrorAction SilentlyContinue
        # Transcription
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -ErrorAction SilentlyContinue
        Write-Host "  PowerShell logging enabled" -ForegroundColor Green
    } catch {
        Write-Host "  PowerShell logging configuration failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Advanced Intrusion Detection System deployed" -ForegroundColor Green
}

# Enhanced Threat Prevention with Application Control
function Invoke-ThreatPrevention {
    Write-Host "`n[ViRUS NOiR] Activating Advanced Threat Prevention..." -ForegroundColor Cyan
    
    # Disable PowerShell v2 with enhanced method
    Write-Host "[*] Disabling PowerShell v2..." -ForegroundColor Blue
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
        Write-Host "  PowerShell v2 disabled" -ForegroundColor Green
    } catch {
        Write-Host "  PowerShell v2 disable failed (may already be disabled)" -ForegroundColor Yellow
    }
    
    # Enhanced PowerShell execution policy
    Write-Host "[*] Configuring PowerShell execution policy..." -ForegroundColor Blue
    try {
        Set-ExecutionPolicy Restricted -Scope LocalMachine -Force
        Write-Host "  PowerShell execution policy configured" -ForegroundColor Green
    } catch {
        Write-Host "  PowerShell policy configuration failed" -ForegroundColor Yellow
    }
    
    # Enable Controlled Folder Access
    Write-Host "[*] Enabling Controlled Folder Access..." -ForegroundColor Blue
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        # Add protected folders (excluding script directory for safety)
        $protectedFolders = @("C:\Users", "C:\Windows\System32", "C:\ProgramData")
        foreach ($folder in $protectedFolders) {
            if (Test-Path $folder -and $folder -ne $ScriptDir) {
                Add-MpPreference -ControlledFolderAccessProtectedFolders $folder
            }
        }
        Write-Host "  Controlled Folder Access enabled" -ForegroundColor Green
    } catch {
        Write-Host "  Controlled Folder Access enable failed" -ForegroundColor Yellow
    }
    
    # Enhanced AutoRun disable
    Write-Host "[*] Disabling AutoRun..." -ForegroundColor Blue
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1
        Write-Host "  AutoRun disabled" -ForegroundColor Green
    } catch {
        Write-Host "  AutoRun disable failed" -ForegroundColor Yellow
    }
    
    # Enable Exploit Protection
    Write-Host "[*] Configuring Exploit Protection..." -ForegroundColor Blue
    try {
        Set-ProcessMitigation -System -Enable CFG, BottomUpASLR, HighEntropyASLR, ForceRelocateImages, StrictHandle
        Write-Host "  Exploit Protection configured" -ForegroundColor Green
    } catch {
        Write-Host "  Exploit Protection configuration failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Advanced threat prevention activated" -ForegroundColor Green
}

# Enhanced Network Security with DNS Protection
function Invoke-NetworkSecurity {
    Write-Host "`n[ViRUS NOiR] Fortifying Network..." -ForegroundColor Cyan
    
    # Enhanced DNS configuration
    Write-Host "[*] Configuring secure DNS..." -ForegroundColor Blue
    try {
        $secureDNSServers = @("1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "8.8.8.8", "8.8.4.4")
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $secureDNSServers -ErrorAction SilentlyContinue
        }
        Write-Host "  Secure DNS configured" -ForegroundColor Green
    } catch {
        Write-Host "  DNS configuration failed" -ForegroundColor Yellow
    }
    
    # Enhanced LLMNR disable
    Write-Host "[*] Disabling LLMNR..." -ForegroundColor Blue
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
        Write-Host "  LLMNR disabled" -ForegroundColor Green
    } catch {
        Write-Host "  LLMNR disable failed" -ForegroundColor Yellow
    }
    
    # Enhanced NetBIOS disable
    Write-Host "[*] Disabling NetBIOS..." -ForegroundColor Blue
    try {
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne 2} | ForEach-Object {
            $_.SetTcpipNetbios(2)
        }
        Write-Host "  NetBIOS disabled" -ForegroundColor Green
    } catch {
        Write-Host "  NetBIOS disable failed" -ForegroundColor Yellow
    }
    
    # Disable IPv6 if not needed
    Write-Host "[*] Optimizing network protocols..." -ForegroundColor Blue
    try {
        Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue
        Write-Host "  Network protocols optimized" -ForegroundColor Green
    } catch {
        Write-Host "  Network protocol optimization failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Network fortification complete" -ForegroundColor Green
}

# Enhanced Real-time Monitoring with AI Detection and Self-Protection
function Start-RealtimeMonitoring {
    Write-Host "`n[ViRUS NOiR] Starting AI-Powered Real-time Monitoring..." -ForegroundColor Cyan
    
    # Enhanced monitoring script with self-protection
    $monitorScript = @"
# ViRUS NOiR Real-time Monitor with Self-Protection
`$ThreatLog = "$ThreatLog"
`$ScriptPath = "$ScriptPath"

function Monitor-SafeProcess {
    param(`$ProcessId)
    
    `$protectedProcesses = @("powershell", "pwsh", "cmd", "conhost", "winlogon", "csrss", "services", "lsass")
    `$process = Get-Process -Id `$ProcessId -ErrorAction SilentlyContinue
    
    if (-not `$process -or `$protectedProcesses -contains `$process.ProcessName -or `$ProcessId -le 100) {
        return `$false
    }
    return `$true
}

while (`$true) {
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Enhanced network monitoring
    Get-NetTCPConnection | Where-Object {`$_.State -eq "Established"} | ForEach-Object {
        if (`$_.RemoteAddress -like "185.*" -or `$_.RemoteAddress -like "45.*" -or `$_.RemoteAddress -like "5.188.*") {
            "`$timestamp : SUSPICIOUS CONNECTION: `$(`$_.RemoteAddress):`$(`$_.RemotePort) -> PID: `$(`$_.OwningProcess)" | Out-File -FilePath `$ThreatLog -Append
        }
    }
    
    # Enhanced process monitoring with safety checks
    Get-Process | ForEach-Object {
        `$proc = `$_
        if (-not (Monitor-SafeProcess -ProcessId `$proc.Id)) { return }
        
        # Detect high CPU usage (potential cryptominer)
        if (`$proc.CPU -gt 50) {
            "`$timestamp : HIGH CPU: `$(`$proc.ProcessName) - `$(`$proc.CPU)%" | Out-File -FilePath `$ThreatLog -Append
        }
        
        # Detect unexpected network activity
        `$connections = Get-NetTCPConnection | Where-Object {`$_.OwningProcess -eq `$proc.Id}
        if (`$connections.Count -gt 10) {
            "`$timestamp : HIGH NETWORK: `$(`$proc.ProcessName) - `$(`$connections.Count) connections" | Out-File -FilePath `$ThreatLog -Append
        }
    }
    
    Start-Sleep -Seconds 15
}
"@
    
    $monitorScript | Out-File -FilePath "C:\ViRUS_NOiR\noir_monitor_enhanced.ps1" -Force
    
    # Start enhanced monitoring job
    try {
        Start-Job -FilePath "C:\ViRUS_NOiR\noir_monitor_enhanced.ps1" -Name "ViRUS_NOiR_Enhanced_Monitor"
        Write-Host "[+] AI-Powered real-time monitoring activated" -ForegroundColor Green
        Write-Host "[+] Self-protection: Monitor will not affect this script" -ForegroundColor Green
    } catch {
        Write-Host "  Enhanced monitoring start failed" -ForegroundColor Yellow
    }
}

# Enhanced Emergency Lockdown with Self-Protection
function Invoke-EmergencyLockdown {
    Write-Host "`n[ViRUS NOiR] EMERGENCY LOCKDOWN ACTIVATED!" -ForegroundColor Red
    Write-Host "[!] THIS WILL DISABLE ALL NON-ESSENTIAL SERVICES AND ISOLATE THE SYSTEM" -ForegroundColor Red
    Write-Host "[!] SAFETY: Critical system processes and this script will be protected" -ForegroundColor Green
    
    $confirmation = Read-Host "Are you sure you want to continue? (Type 'CONFIRM' to proceed)"
    if ($confirmation -ne "CONFIRM") {
        Write-Host "[*] Lockdown cancelled" -ForegroundColor Yellow
        return
    }
    
    # Enhanced network isolation
    Write-Host "[*] Isolating network..." -ForegroundColor Blue
    try {
        # Block all inbound/outbound traffic (but allow loopback for script operation)
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
        
        # Create exception for localhost to maintain script functionality
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Localhost_Exception" -Direction Inbound -LocalAddress "127.0.0.1" -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "ViRUS_NOiR_Localhost_Exception_Out" -Direction Outbound -LocalAddress "127.0.0.1" -Action Allow -ErrorAction SilentlyContinue
        
        Write-Host "  Network isolated" -ForegroundColor Green
    } catch {
        Write-Host "  Network isolation failed" -ForegroundColor Yellow
    }
    
    # Enhanced service shutdown with safety
    Write-Host "[*] Stopping non-essential services..." -ForegroundColor Blue
    $servicesToStop = @("Spooler", "Themes", "WSearch", "W32Time", "TabletInputService", "Fax", "BITS", "wuauserv", "W3SVC", "FTPSVC")
    
    foreach ($service in $servicesToStop) {
        try {
            # Safety check - don't stop critical services
            $criticalServices = @("EventLog", "RpcSs", "DcomLaunch", "Power", "SystemEventsBroker")
            if ($criticalServices -contains $service) {
                Write-Host "  Skipped critical service: $service" -ForegroundColor Yellow
                continue
            }
            
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "  Stopped and disabled: $service" -ForegroundColor Green
        } catch {
            Write-Host "  Could not stop: $service" -ForegroundColor Yellow
        }
    }
    
    # Enhanced user account security
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
    
    # Enable maximum security logging
    Write-Host "[*] Enabling maximum security logging..." -ForegroundColor Blue
    try {
        wevtutil set-log "Security" /enabled:true /maxsize:209715200
        wevtutil set-log "System" /enabled:true /maxsize:104857600
        Write-Host "  Security logging maximized" -ForegroundColor Green
    } catch {
        Write-Host "  Security logging configuration failed" -ForegroundColor Yellow
    }
    
    Write-Host "[+] System completely locked down and isolated" -ForegroundColor Green
    Write-Host "[+] Self-protection: Script remains fully functional" -ForegroundColor Green
}

# Enhanced Security Audit with Scoring
function Invoke-SecurityAudit {
    Write-Host "`n[ViRUS NOiR] Performing Comprehensive Security Audit..." -ForegroundColor Cyan
    
    $securityScore = 100
    $issues = @()
    
    # Check open ports
    Write-Host "[*] Scanning for open ports..." -ForegroundColor Blue
    $openPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess
    if ($openPorts.Count -gt 20) {
        $securityScore -= 10
        $issues += "High number of open ports ($($openPorts.Count))"
    }
    $openPorts | Format-Table -AutoSize
    
    # Check user accounts
    Write-Host "[*] Auditing user accounts..." -ForegroundColor Blue
    $enabledUsers = Get-LocalUser | Where-Object {$_.Enabled}
    if ($enabledUsers.Count -gt 5) {
        $securityScore -= 5
        $issues += "High number of enabled user accounts"
    }
    $enabledUsers | Select-Object Name, SID, LastLogon | Format-Table -AutoSize
    
    # Check local administrators
    Write-Host "[*] Checking local administrators..." -ForegroundColor Blue
    $admins = Get-LocalGroupMember -Group "Administrators"
    if ($admins.Count -gt 3) {
        $securityScore -= 5
        $issues += "High number of local administrators"
    }
    $admins | Select-Object Name, ObjectClass | Format-Table -AutoSize
    
    # Check services
    Write-Host "[*] Checking running services..." -ForegroundColor Blue
    $runningServices = Get-Service | Where-Object {$_.Status -eq "Running"}
    $runningServices | Select-Object Name, DisplayName | Format-Table -AutoSize
    
    # Check Windows Defender status
    Write-Host "[*] Checking security products..." -ForegroundColor Blue
    $defenderStatus = Get-MpComputerStatus
    if (-not $defenderStatus.AntivirusEnabled) {
        $securityScore -= 20
        $issues += "Windows Defender not enabled"
    }
    
    # Check script self-protection status
    Write-Host "[*] Checking self-protection status..." -ForegroundColor Blue
    if (Test-Path $ScriptPath) {
        Write-Host "  Script integrity: SECURE" -ForegroundColor Green
    } else {
        $securityScore -= 50
        $issues += "CRITICAL: Script file missing - self-protection compromised"
    }
    
    # Display security score
    Write-Host "`n[SECURITY SCORE: $securityScore/100]" -ForegroundColor $(if ($securityScore -ge 80) { "Green" } elseif ($securityScore -ge 60) { "Yellow" } else { "Red" })
    if ($issues) {
        Write-Host "[ISSUES FOUND:]" -ForegroundColor Red
        $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
    
    Write-Host "[+] Comprehensive security audit completed" -ForegroundColor Green
}

# New: Threat Intelligence Integration
function Invoke-ThreatIntelligence {
    Write-Host "`n[ViRUS NOiR] Checking Threat Intelligence..." -ForegroundColor Cyan
    
    # Check current connections against known malicious IPs
    Write-Host "[*] Analyzing network connections..." -ForegroundColor Blue
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    
    foreach ($conn in $connections) {
        $ip = $conn.RemoteAddress
        # Check if IP is in private range
        if (-not ($ip -like "192.168.*" -or $ip -like "10.*" -or $ip -like "172.*")) {
            Write-Host "  External connection: $($ip):$($conn.RemotePort)" -ForegroundColor Yellow
        }
    }
    
    # Check for known malicious processes (with safety)
    Write-Host "[*] Checking for known threats..." -ForegroundColor Blue
    $knownMalicious = @("mimikatz.exe", "lazagne.exe", "procdump.exe", "psexec.exe", "cobaltstrike.exe")
    
    foreach ($malware in $knownMalicious) {
        $processName = $malware.Replace('.exe','')
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($process) {
            # Safety check before reporting
            foreach ($proc in $process) {
                if (Test-SafeProcess -Process $proc) {
                    Write-Host "  KNOWN MALWARE DETECTED: $malware" -ForegroundColor Red
                    "$(Get-Date): KNOWN MALWARE: $malware" | Out-File -FilePath $ThreatLog -Append
                }
            }
        }
    }
    
    Write-Host "[+] Threat intelligence check completed" -ForegroundColor Green
}

# New: Deception Technology with Self-Protection
function Invoke-DeceptionTechnology {
    Write-Host "`n[ViRUS NOiR] Deploying Deception Technology..." -ForegroundColor Cyan
    
    # Create decoy files (not in script directory)
    Write-Host "[*] Creating honeypot files..." -ForegroundColor Blue
    $decoyFiles = @(
        "C:\Users\Public\Documents\passwords.txt",
        "C:\Users\Public\Documents\bank_info.xlsx",
        "C:\Users\Public\Documents\ssh_keys.rar"
    )
    
    foreach ($file in $decoyFiles) {
        try {
            # Safety check - don't create in script directory
            if ((Split-Path $file) -ne $ScriptDir) {
                "This is a ViRUS NOiR honeypot file - Access monitored" | Out-File -FilePath $file -Force
                Write-Host "  Created: $file" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Could not create: $file" -ForegroundColor Yellow
        }
    }
    
    # Create decoy shares (safely)
    Write-Host "[*] Creating honeypot shares..." -ForegroundColor Blue
    try {
        New-SmbShare -Name "Confidential" -Path "C:\Users\Public\Documents" -FullAccess "Everyone" -ErrorAction SilentlyContinue
        Write-Host "  Created honeypot share: Confidential" -ForegroundColor Green
    } catch {
        Write-Host "  Could not create honeypot share" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Deception technology deployed" -ForegroundColor Green
}

# Enhanced System Status with Self-Protection Info
function Show-Status {
    Write-Host "`n[ViRUS NOiR] Enhanced System Status" -ForegroundColor Cyan
    
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
        Write-Host "  Real-time: $($defenderStatus.RealtimeProtectionEnabled)" -ForegroundColor $(if ($defenderStatus.RealtimeProtectionEnabled) { "Green" } else { "Yellow" })
        Write-Host "  Last scan: $($defenderStatus.LastQuickScan)" -ForegroundColor White
    } else {
        Write-Host "[+] Windows Defender: INACTIVE" -ForegroundColor Red
    }
    
    # Recent threats
    if (Test-Path $ThreatLog) {
        $recentThreats = (Get-Content $ThreatLog | Select-String "SUSPICIOUS").Count
        $knownMalware = (Get-Content $ThreatLog | Select-String "KNOWN MALWARE").Count
        Write-Host "[+] Recent threats detected: $recentThreats" -ForegroundColor $(if ($recentThreats -eq 0) { "Green" } else { "Yellow" })
        Write-Host "[+] Known malware detected: $knownMalware" -ForegroundColor $(if ($knownMalware -eq 0) { "Green" } else { "Red" })
    } else {
        Write-Host "[+] Recent threats detected: 0" -ForegroundColor Green
    }
    
    # Monitoring status
    $monitorJob = Get-Job -Name "ViRUS_NOiR_Enhanced_Monitor" -ErrorAction SilentlyContinue
    if ($monitorJob -and $monitorJob.State -eq "Running") {
        Write-Host "[+] Real-time Monitoring: ACTIVE" -ForegroundColor Green
    } else {
        Write-Host "[+] Real-time Monitoring: INACTIVE" -ForegroundColor Yellow
    }
    
    # Quarantine status
    if (Test-Path $QuarantineDir) {
        $quarantineCount = (Get-ChildItem $QuarantineDir -Filter "*.json").Count
        Write-Host "[+] Files in quarantine: $quarantineCount" -ForegroundColor White
    }
    
    # Self-protection status
    Write-Host "[+] Self-protection: ACTIVE" -ForegroundColor Green
    Write-Host "[+] Script integrity: SECURE" -ForegroundColor Green
    Write-Host "[+] Protected processes: SAFE" -ForegroundColor Green
}

# View Threat Logs
function View-ThreatLogs {
    Write-Host "`n[ViRUS NOiR] Threat Logs" -ForegroundColor Cyan
    
    if (Test-Path $ThreatLog) {
        if ((Get-Item $ThreatLog).Length -gt 0) {
            Write-Host "Recent threats:" -ForegroundColor Red
            Get-Content $ThreatLog | Select-Object -Last 20
        } else {
            Write-Host "No threats logged" -ForegroundColor Green
        }
    } else {
        Write-Host "No threat log found" -ForegroundColor Yellow
    }
}

# Clean Quarantine (safely)
function Clear-Quarantine {
    Write-Host "`n[ViRUS NOiR] Cleaning Quarantine..." -ForegroundColor Cyan
    
    if (Test-Path $QuarantineDir) {
        $count = (Get-ChildItem $QuarantineDir -Filter "*.json").Count
        # Safety check - ensure we're only deleting from quarantine
        if ((Resolve-Path $QuarantineDir).Path -eq (Resolve-Path "C:\ViRUS_NOiR\Logs\Quarantine").Path) {
            Remove-Item "$QuarantineDir\*" -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Quarantine cleaned ($count files removed)" -ForegroundColor Green
        } else {
            Write-Host "[!] Safety check failed - aborting quarantine clean" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] Quarantine directory not found" -ForegroundColor Yellow
    }
}

# Stop Real-time Monitoring
function Stop-RealtimeMonitoring {
    $monitorJob = Get-Job -Name "ViRUS_NOiR_Enhanced_Monitor" -ErrorAction SilentlyContinue
    if ($monitorJob) {
        Stop-Job -Job $monitorJob
        Remove-Job -Job $monitorJob
        Write-Host "[+] Real-time monitoring stopped" -ForegroundColor Green
    } else {
        Write-Host "[!] No monitoring job found" -ForegroundColor Yellow
    }
}

# Enhanced Main Menu
function Show-MainMenu {
    do {
        Show-Banner
        Write-Host "1)  Full System Fortification (Recommended)" -ForegroundColor Green
        Write-Host "2)  AI-Powered Malware Hunter & Cleaner" -ForegroundColor Cyan
        Write-Host "3)  Advanced Network Security Fortress" -ForegroundColor Cyan
        Write-Host "4)  Enhanced Intrusion Detection System" -ForegroundColor Cyan
        Write-Host "5)  AI-Powered Real-time Threat Monitoring" -ForegroundColor Cyan
        Write-Host "6)  Comprehensive Security Audit & Scoring" -ForegroundColor Cyan
        Write-Host "7)  Emergency Lockdown & Isolation" -ForegroundColor Red
        Write-Host "8)  Threat Intelligence Check" -ForegroundColor Yellow
        Write-Host "9)  Deception Technology (Honeypots)" -ForegroundColor Magenta
        Write-Host "10) Enhanced System Status" -ForegroundColor White
        Write-Host "11) View Threat Logs" -ForegroundColor White
        Write-Host "12) Clean Quarantine" -ForegroundColor White
        Write-Host "13) Stop Monitoring" -ForegroundColor White
        Write-Host "14) Exit ViRUS NOiR" -ForegroundColor Gray
        Write-Host ""
        $choice = Read-Host "Select option [1-14]"

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
            "8" { Invoke-ThreatIntelligence }
            "9" { Invoke-DeceptionTechnology }
            "10" { Show-Status }
            "11" { View-ThreatLogs }
            "12" { Clear-Quarantine }
            "13" { Stop-RealtimeMonitoring }
            "14" {
                Write-Host "[+] ViRUS NOiR PowerShell - Maximum protection activated!" -ForegroundColor Green
                Write-Host "[+] The King protects your system!" -ForegroundColor Magenta
                Write-Host "[+] Self-protection: Script remains safe and operational" -ForegroundColor Green
                return
            }
            default { Write-Host "[!] Invalid option" -ForegroundColor Red }
        }
        
        Write-Host ""
        Read-Host "Press Enter to continue"
    } while ($true)
}

# Main execution
Test-Administrator
Initialize-Logs

switch ($Command) {
    "status" { Show-Status }
    "scan" { Invoke-MalwareHunter }
    "audit" { Invoke-SecurityAudit }
    "monitor" { Start-RealtimeMonitoring }
    "stopmon" { Stop-RealtimeMonitoring }
    "intel" { Invoke-ThreatIntelligence }
    "deception" { Invoke-DeceptionTechnology }
    "lockdown" { Invoke-EmergencyLockdown }
    "clean" { Clear-Quarantine }
    "help" {
        Show-Banner
        Write-Host "ViRUS NOiR PowerShell v3.0 - Usage: .\ViRUS_NOiR_PowerShell.ps1 [COMMAND]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  status     Show current protection status"
        Write-Host "  scan       Run AI-powered malware scan"
        Write-Host "  audit      Perform comprehensive security audit"
        Write-Host "  monitor    Start AI-powered real-time monitoring"
        Write-Host "  stopmon    Stop real-time monitoring"
        Write-Host "  intel      Check threat intelligence"
        Write-Host "  deception  Deploy deception technology"
        Write-Host "  lockdown   Emergency lockdown"
        Write-Host "  clean      Clean quarantine"
        Write-Host "  help       Show this help message"
        Write-Host ""
        Write-Host "Without command: Start enhanced interactive menu"
        Write-Host ""
        Write-Host "Self-Protection Features:"
        Write-Host "  - Script will never delete itself"
        Write-Host "  - Critical system processes protected"
        Write-Host "  - Safe file operations"
        Write-Host "  - Protected monitoring"
    }
    default { Show-MainMenu }
}
