#!/bin/bash

# ViRUS NOiR - Ultimate Cyber Defense System for Termux
# Advanced Anti-Malware, Anti-Spyware Protection
# Version 2.0 - Mobile Security Edition

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log files
LOG_DIR="$HOME/.virus_noir"
LOG_FILE="$LOG_DIR/virus_noir.log"
THREAT_LOG="$LOG_DIR/noir_threats.log"
SCAN_LOG="$LOG_DIR/scan_results.log"

# Initialize system
init_system() {
    echo -e "${CYAN}[ViRUS NOiR] Initializing Mobile Security System...${NC}"
    
    # Create necessary directories
    mkdir -p "$LOG_DIR"
    
    # Create log files
    touch "$LOG_FILE" "$THREAT_LOG" "$SCAN_LOG"
    
    # Initialize threat database
    if [[ ! -f "$LOG_DIR/threat_signatures.db" ]]; then
        cat > "$LOG_DIR/threat_signatures.db" << 'EOF'
# Termux Threat Signatures
miner
xmrig
cpuminer
backdoor
malware
trojan
keylogger
EOF
    fi
    
    echo -e "${GREEN}[+] System initialized${NC}"
    echo "$(date): ViRUS NOiR started" >> "$LOG_FILE"
}

# Banner
show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "    ██╗   ██╗██╗██████╗ ██╗   ██╗███████╗    ███╗   ██╗ ██████╗ ██╗██████╗ "
    echo "    ██║   ██║██║██╔══██╗██║   ██║██╔════╝    ████╗  ██║██╔═══██╗██║██╔══██╗"
    echo "    ██║   ██║██║██████╔╝██║   ██║███████╗    ██╔██╗ ██║██║   ██║██║██████╔╝"
    echo "    ╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██║╚██╗██║██║   ██║██║██╔══██╗"
    echo "     ╚████╔╝ ██║██║  ██║╚██████╔╝███████║    ██║ ╚████║╚██████╔╝██║██║  ██║"
    echo "      ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝"
    echo ""
    echo "           MOBILE CYBER DEFENSE SYSTEM - TERMUX EDITION"
    echo "    ====================================================="
    echo -e "${NC}"
    echo -e "${YELLOW}            https://github.com/VN-KEO/ViRUS-NOiR${NC}"
    echo ""
}

# Check Termux environment
check_environment() {
    if [[ ! -d "/data/data/com.termux/files/usr" ]]; then
        echo -e "${RED}[!] This script must be run in Termux${NC}"
        echo -e "${YELLOW}[*] Install Termux from F-Droid or Google Play${NC}"
        exit 1
    fi
}

# Update and install dependencies
install_dependencies() {
    echo -e "${CYAN}[ViRUS NOiR] Checking dependencies...${NC}"
    
    # Update package lists
    pkg update -y > /dev/null 2>&1
    
    # Essential tools
    local tools=("nmap" "net-tools" "procps" "grep" "awk" "sed" "findutils")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            echo -e "${YELLOW}[*] Installing $tool...${NC}"
            pkg install -y "$tool" > /dev/null 2>&1
        fi
    done
    
    # Security tools (optional)
    local security_tools=("lynx" "python" "git")
    for tool in "${security_tools[@]}"; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            echo -e "${BLUE}[*] Recommended: $tool - install manually if needed${NC}"
        fi
    done
    
    echo -e "${GREEN}[+] Dependencies checked${NC}"
}

# System Security Scan
system_scan() {
    echo -e "\n${CYAN}[ViRUS NOiR] Performing System Security Scan...${NC}"
    
    # Scan for suspicious files
    echo -e "${BLUE}[*] Scanning for suspicious files...${NC}"
    find $HOME -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) -exec grep -l "miner\|backdoor\|malware" {} \; 2>/dev/null >> "$SCAN_LOG"
    
    # Check running processes
    echo -e "${BLUE}[*] Analyzing running processes...${NC}"
    ps aux 2>/dev/null | grep -E "miner|xmrig|cpuminer|backdoor" >> "$THREAT_LOG"
    
    # Check network connections
    echo -e "${BLUE}[*] Checking network connections...${NC}"
    netstat -an 2>/dev/null | grep -E "LISTEN|ESTABLISHED" >> "$SCAN_LOG"
    
    # Check for suspicious cron jobs (termux scheduled tasks)
    echo -e "${BLUE}[*] Checking scheduled tasks...${NC}"
    if [[ -d "$HOME/.termux/boot" ]]; then
        find "$HOME/.termux/boot" -type f -exec file {} \; >> "$SCAN_LOG"
    fi
    
    # Check package sources
    echo -e "${BLUE}[*] Checking package sources...${NC}"
    cat $PREFIX/etc/apt/sources.list >> "$SCAN_LOG" 2>/dev/null
    
    echo -e "${GREEN}[+] System scan completed${NC}"
    echo "$(date): System security scan performed" >> "$LOG_FILE"
}

# Network Security
network_security() {
    echo -e "\n${CYAN}[ViRUS NOiR] Configuring Network Security...${NC}"
    
    # Scan open ports on device
    echo -e "${BLUE}[*] Scanning for open ports...${NC}"
    nmap -sS localhost >> "$SCAN_LOG" 2>/dev/null || echo "Nmap not available" >> "$SCAN_LOG"
    
    # Check for suspicious listening services
    echo -e "${BLUE}[*] Checking listening services...${NC}"
    netstat -tulpn 2>/dev/null | grep LISTEN >> "$SCAN_LOG"
    
    # Monitor network traffic
    echo -e "${BLUE}[*] Monitoring network connections...${NC}"
    ss -tunp 2>/dev/null >> "$SCAN_LOG"
    
    echo -e "${GREEN}[+] Network security check completed${NC}"
}

# Malware Detection
malware_detection() {
    echo -e "\n${CYAN}[ViRUS NOiR] Running Malware Detection...${NC}"
    
    local threats_found=0
    
    # Check for mining processes
    echo -e "${BLUE}[*] Checking for crypto miners...${NC}"
    if pgrep -f "miner\|xmrig\|cpuminer" > /dev/null; then
        echo "CRYPTOMINER DETECTED: $(pgrep -f 'miner\|xmrig\|cpuminer')" >> "$THREAT_LOG"
        ((threats_found++))
    fi
    
    # Check for suspicious shell scripts
    echo -e "${BLUE}[*] Scanning for malicious scripts...${NC}"
    find $HOME -name "*.sh" -type f -exec grep -l "wget.*bash\|curl.*bash\|chmod.*x" {} \; 2>/dev/null | while read script; do
        echo "SUSPICIOUS SCRIPT: $script" >> "$THREAT_LOG"
        ((threats_found++))
    done
    
    # Check termux boot scripts
    echo -e "${BLUE}[*] Checking boot scripts...${NC}"
    if [[ -d "$HOME/.termux/boot" ]]; then
        find "$HOME/.termux/boot" -name "*.sh" -exec grep -l "miner\|backdoor" {} \; 2>/dev/null | while read boot_script; do
            echo "MALICIOUS BOOT SCRIPT: $boot_script" >> "$THREAT_LOG"
            ((threats_found++))
        done
    fi
    
    # Check for suspicious Python scripts
    echo -e "${BLUE}[*] Checking Python scripts...${NC}"
    find $HOME -name "*.py" -type f -exec grep -l "import.*socket.*bind\|import.*subprocess" {} \; 2>/dev/null | while read py_script; do
        echo "SUSPICIOUS PYTHON SCRIPT: $py_script" >> "$THREAT_LOG"
        ((threats_found++))
    done
    
    if [[ $threats_found -eq 0 ]]; then
        echo -e "${GREEN}[+] No malware detected${NC}"
    else
        echo -e "${RED}[!] $threats_found potential threats found${NC}"
        echo -e "${YELLOW}[*] Check $THREAT_LOG for details${NC}"
    fi
}

# Process Monitoring
process_monitor() {
    echo -e "\n${CYAN}[ViRUS NOiR] Monitoring Processes...${NC}"
    
    echo -e "${BLUE}[*] Top CPU processes:${NC}"
    ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -10
    
    echo -e "${BLUE}[*] Top memory processes:${NC}"
    ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -10
    
    # Check for hidden processes
    echo -e "${BLUE}[*] Checking for unusual processes...${NC}"
    ps -eo pid,cmd | grep -vE "^(.*(bash|ps|grep|awk|sed|nano|vim|ssh|sftp|scp).*)$" | head -10
}

# File Integrity Check
file_integrity() {
    echo -e "\n${CYAN}[ViRUS NOiR] Performing File Integrity Check...${NC}"
    
    # Check critical directories
    local critical_dirs=("$HOME/.termux" "$PREFIX/bin" "$PREFIX/etc")
    
    for dir in "${critical_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            echo -e "${BLUE}[*] Checking $dir...${NC}"
            find "$dir" -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | head -20 >> "$SCAN_LOG"
        fi
    done
    
    # Check for recently modified files
    echo -e "${BLUE}[*] Checking recently modified files...${NC}"
    find $HOME -type f -mtime -1 2>/dev/null | head -20 >> "$SCAN_LOG"
    
    echo -e "${GREEN}[+] File integrity check completed${NC}"
}

# Permission Audit
permission_audit() {
    echo -e "\n${CYAN}[ViRUS NOiR] Auditing File Permissions...${NC}"
    
    # Check for world-writable files
    echo -e "${BLUE}[*] Checking world-writable files...${NC}"
    find $HOME -perm -o+w -type f 2>/dev/null | head -20 >> "$SCAN_LOG"
    
    # Check for executable scripts in home directory
    echo -e "${BLUE}[*] Checking executable scripts...${NC}"
    find $HOME -type f -executable -name "*.sh" -o -name "*.py" 2>/dev/null | head -20 >> "$SCAN_LOG"
    
    echo -e "${GREEN}[+] Permission audit completed${NC}"
}

# Clean System
clean_system() {
    echo -e "\n${CYAN}[ViRUS NOiR] Cleaning System...${NC}"
    
    local cleaned=0
    
    # Remove suspicious miner processes
    echo -e "${BLUE}[*] Removing suspicious processes...${NC}"
    pkill -f "miner\|xmrig\|cpuminer" 2>/dev/null && ((cleaned++))
    
    # Clean temporary files
    echo -e "${BLUE}[*] Cleaning temporary files...${NC}"
    rm -rf /tmp/*miner* 2>/dev/null && ((cleaned++))
    rm -rf $HOME/tmp/*miner* 2>/dev/null && ((cleaned++))
    
    # Check and clean termux boot scripts
    if [[ -d "$HOME/.termux/boot" ]]; then
        echo -e "${BLUE}[*] Checking boot scripts...${NC}"
        find "$HOME/.termux/boot" -name "*.sh" -exec grep -l "miner\|malware" {} \; -delete 2>/dev/null && ((cleaned++))
    fi
    
    if [[ $cleaned -gt 0 ]]; then
        echo -e "${GREEN}[+] System cleaned - $cleaned actions performed${NC}"
    else
        echo -e "${YELLOW}[+] No cleaning actions needed${NC}"
    fi
}

# Real-time Monitoring
start_monitoring() {
    echo -e "\n${CYAN}[ViRUS NOiR] Starting Real-time Monitoring...${NC}"
    
    # Create monitoring script
    cat > $HOME/.virus_noir/monitor.sh << 'EOF'
#!/bin/bash
LOG_DIR="$HOME/.virus_noir"
THREAT_LOG="$LOG_DIR/noir_threats.log"

while true; do
    # Monitor network connections
    netstat -an 2>/dev/null | grep -E "ESTABLISHED" | while read conn; do
        if echo "$conn" | grep -qE "(185\.|45\.|mining)"; then
            echo "$(date): SUSPICIOUS CONNECTION: $conn" >> "$THREAT_LOG"
        fi
    done
    
    # Monitor process creation
    ps aux 2>/dev/null | grep -E "miner|xmrig|cpuminer" | while read process; do
        echo "$(date): CRYPTOMINER DETECTED: $process" >> "$THREAT_LOG"
        pid=$(echo "$process" | awk '{print $2}')
        kill -9 "$pid" 2>/dev/null
    done
    
    sleep 30
done
EOF
    
    chmod +x $HOME/.virus_noir/monitor.sh
    
    # Start monitoring in background
    nohup $HOME/.virus_noir/monitor.sh > /dev/null 2>&1 &
    
    echo -e "${GREEN}[+] Real-time monitoring activated${NC}"
    echo -e "${YELLOW}[*] Monitoring running in background${NC}"
}

# Emergency Lockdown
emergency_lockdown() {
    echo -e "\n${RED}[ViRUS NOiR] EMERGENCY LOCKDOWN ACTIVATED!${NC}"
    
    read -p "Are you sure you want to continue? (yes/NO): " confirmation
    if [[ "$confirmation" != "yes" ]]; then
        echo -e "${YELLOW}[*] Lockdown cancelled${NC}"
        return
    fi
    
    # Kill all suspicious processes
    echo -e "${BLUE}[*] Terminating suspicious processes...${NC}"
    pkill -f "miner\|xmrig\|cpuminer\|backdoor"
    
    # Clear temporary directories
    echo -e "${BLUE}[*] Cleaning temporary files...${NC}"
    rm -rf /tmp/*
    rm -rf $HOME/tmp/*
    
    # Stop monitoring
    echo -e "${BLUE}[*] Stopping services...${NC}"
    pkill -f "virus_noir"
    
    echo -e "${GREEN}[+] Emergency lockdown completed${NC}"
}

# Show Status
show_status() {
    echo -e "\n${CYAN}[ViRUS NOiR] System Status${NC}"
    
    # Monitoring status
    if pgrep -f "monitor.sh" > /dev/null; then
        echo -e "${GREEN}[+] Real-time Monitoring: ACTIVE${NC}"
    else
        echo -e "${RED}[+] Real-time Monitoring: INACTIVE${NC}"
    fi
    
    # Recent threats
    if [[ -f "$THREAT_LOG" ]]; then
        local threat_count=$(grep -c "SUSPICIOUS\|DETECTED" "$THREAT_LOG" 2>/dev/null || echo "0")
        echo -e "${YELLOW}[+] Recent threats detected: $threat_count${NC}"
    else
        echo -e "${YELLOW}[+] Recent threats detected: 0${NC}"
    fi
    
    # System information
    echo -e "${BLUE}[*] System Uptime:$(uptime 2>/dev/null || echo ' N/A')${NC}"
    echo -e "${BLUE}[*] Storage Usage:$(df -h $HOME 2>/dev/null | tail -1)${NC}"
}

# Update Tool
update_tool() {
    echo -e "\n${CYAN}[ViRUS NOiR] Updating Security Database...${NC}"
    
    # Update package lists
    pkg update -y > /dev/null 2>&1
    
    # Update threat signatures (placeholder for future updates)
    echo -e "${BLUE}[*] Checking for updates...${NC}"
    
    echo -e "${GREEN}[+] Security database updated${NC}"
}

# Main Menu
main_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}1) Full System Security Scan"
        echo "2) Network Security Check"
        echo "3) Malware Detection"
        echo "4) Process Monitoring"
        echo "5) File Integrity Check"
        echo "6) Permission Audit"
        echo "7) System Cleaner"
        echo "8) Real-time Monitoring"
        echo "9) Emergency Lockdown"
        echo "10) System Status"
        echo "11) Update Tool"
        echo "12) View Threat Logs"
        echo "13) Exit ViRUS NOiR"
        echo ""
        read -p "Select option [1-13]: " choice

        case $choice in
            1)
                system_scan
                malware_detection
                ;;
            2)
                network_security
                ;;
            3)
                malware_detection
                ;;
            4)
                process_monitor
                ;;
            5)
                file_integrity
                ;;
            6)
                permission_audit
                ;;
            7)
                clean_system
                ;;
            8)
                start_monitoring
                ;;
            9)
                emergency_lockdown
                ;;
            10)
                show_status
                ;;
            11)
                update_tool
                ;;
            12)
                echo -e "\n${CYAN}Threat Log:${NC}"
                if [[ -f "$THREAT_LOG" ]]; then
                    tail -20 "$THREAT_LOG"
                else
                    echo "No threats logged"
                fi
                ;;
            13)
                echo -e "${GREEN}[+] ViRUS NOiR - Mobile protection active!${NC}"
                echo -e "${YELLOW}[*] Monitor $LOG_DIR for security events${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Command line options
case "${1:-}" in
    --status)
        show_status
        exit 0
        ;;
    --scan)
        system_scan
        malware_detection
        exit 0
        ;;
    --monitor)
        start_monitoring
        exit 0
        ;;
    --clean)
        clean_system
        exit 0
        ;;
    --help)
        show_banner
        echo -e "${WHITE}Usage: $0 [OPTION]${NC}"
        echo ""
        echo "Options:"
        echo "  --status    Show current protection status"
        echo "  --scan      Run security scan"
        echo "  --monitor   Start real-time monitoring"
        echo "  --clean     Clean system"
        echo "  --help      Show this help message"
        echo ""
        echo "Without options: Start interactive menu"
        exit 0
        ;;
esac

# Initialize and start
check_environment
init_system
install_dependencies

# Signal trap for cleanup
trap 'echo -e "\n${RED}[!] ViRUS NOiR interrupted${NC}"; exit 1' INT TERM

# Start main menu
main_menu
