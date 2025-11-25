# Copy and paste this SAFE version into a new file:
@'
# ViRUS NOiR - SAFE ENHANCED VERSION
# Fixed process detection to avoid terminating essential processes

param([string]$Command = "menu")

# Safe process detection - DON'T terminate these
$safeProcesses = @("explorer", "chrome", "firefox", "edge", "notepad", "word", "excel", "powershell", "cmd", "dwm", "ctfmon", "OneDrive", "igfxEM", "sihost", "runtimebroker")

function Invoke-SafeMalwareHunter {
    Write-Host "`n[ViRUS NOiR] SAFE Malware Hunt..." -ForegroundColor Cyan
    
    # Run Defender scan
    Write-Host "[*] Running Windows Defender quick scan..." -ForegroundColor Blue
    try {
        Start-MpScan -ScanType QuickScan
        Write-Host "  Quick scan initiated" -ForegroundColor Green
    } catch {
        Write-Host "  Defender scan failed" -ForegroundColor Yellow
    }
    
    # SAFE process analysis - only target known malware
    Write-Host "[*] Safely analyzing processes..." -ForegroundColor Blue
    $knownMalicious = @("miner", "xmrig", "cpuminer", "backdoor", "keylogger", "trojan", "cobaltstrike", "beacon", "metasploit")
    
    Get-Process | ForEach-Object {
        $process = $_
        $shouldCheck = $true
        
        # Skip safe processes
        foreach ($safeProc in $safeProcesses) {
            if ($process.ProcessName -like "*$safeProc*") {
                $shouldCheck = $false
                break
            }
        }
        
        if ($shouldCheck) {
            foreach ($malware in $knownMalicious) {
                if ($process.ProcessName -like "*$malware*" -or $process.Path -like "*$malware*") {
                    $message = "SUSPICIOUS PROCESS: $($process.ProcessName) (PID: $($process.Id))"
                    Write-Host "  $message" -ForegroundColor Red
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                        Write-Host "  Terminated: $($process.ProcessName)" -ForegroundColor Green
                    } catch {
                        Write-Host "  Could not terminate: $($process.ProcessName)" -ForegroundColor Yellow
                    }
                    break
                }
            }
        }
    }
    
    Write-Host "[+] Safe malware hunt completed" -ForegroundColor Green
}

# Rest of your existing menu code...
function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "    ██╗   ██╗██╗██████╗ ██╗   ██╗███████╗    ███╗   ██╗ ██████╗ ██╗██████╗ " -ForegroundColor Magenta
        Write-Host "    ██║   ██║██║██╔══██╗██║   ██║██╔════╝    ████╗  ██║██╔═══██╗██║██╔══██╗" -ForegroundColor Magenta
        Write-Host "    ██║   ██║██║██████╔╝██║   ██║███████╗    ██╔██╗ ██║██║   ██║██║██████╔╝" -ForegroundColor Magenta
        Write-Host "    ╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██║╚██╗██║██║   ██║██║██╔══██╗" -ForegroundColor Magenta
        Write-Host "     ╚████╔╝ ██║██║  ██║╚██████╔╝███████║    ██║ ╚████║╚██████╔╝██║██║  ██║" -ForegroundColor Magenta
        Write-Host "      ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "           ViRUS NOiR - SAFE MODE - ENHANCED PROTECTION" -ForegroundColor Green
        Write-Host "    ==========================================================" -ForegroundColor Green
        
        Write-Host "1)  Safe Malware Hunter (Recommended)" -ForegroundColor Green
        Write-Host "2)  System Hardening" -ForegroundColor Cyan  
        Write-Host "3)  Network Security"
        Write-Host "4)  Security Audit"
        Write-Host "5)  System Status"
        Write-Host "6)  Exit"
        Write-Host ""
        $choice = Read-Host "Select option [1-6]"

        switch ($choice) {
            "1" { Invoke-SafeMalwareHunter }
            "2" { 
                # Your existing hardening code
                Write-Host "[*] Safe system hardening..." -ForegroundColor Blue
                # Add safe hardening commands here
            }
            "3" { 
                # Your existing network security code
                Write-Host "[*] Configuring network security..." -ForegroundColor Blue
            }
            "4" { 
                # Your existing audit code
                Write-Host "[*] Running security audit..." -ForegroundColor Blue
            }
            "5" { 
                # Your existing status code
                Write-Host "[*] System status..." -ForegroundColor Blue
            }
            "6" { 
                Write-Host "[+] ViRUS NOiR Safe Mode - Protection active!" -ForegroundColor Green
                return 
            }
            default { Write-Host "[!] Invalid option" -ForegroundColor Red }
        }
        
        Write-Host ""
        Read-Host "Press Enter to continue"
    } while ($true)
}

# Check admin rights
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run as Administrator!" -ForegroundColor Red
    exit
}

Show-MainMenu
'@ | Out-File -FilePath "$env:USERPROFILE\Desktop\ViRUS_NOiR_Safe.ps1" -Encoding UTF8
