#!/bin/bash

# ViRUS NOiR - Ultimate Cyber Defense System
# Advanced Anti-Malware, Anti-Spyware, Anti-Hacker Protection
# Version 2.0 - The King of Cyber Defense

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/virus_noir.log"
THREAT_LOG="/var/log/noir_threats.log"

# Initialize logs
init_logs() {
    sudo touch "$LOG_FILE" "$THREAT_LOG"
    sudo chmod 600 "$LOG_FILE" "$THREAT_LOG"
    echo "$(date): ViRUS NOiR Started" | sudo tee -a "$LOG_FILE" > /dev/null
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
    echo "              ULTIMATE CYBER DEFENSE SYSTEM - THE KING OF PROTECTION"
    echo "    ==================================================================="
    echo -e "${NC}"
}

# Check root privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] ViRUS NOiR requires root privileges!${NC}"
        echo -e "${YELLOW}[*] Please run: sudo $0${NC}"
        exit 1
    fi
}

# System Hardening
harden_system() {
    echo -e "\n${CYAN}[ViRUS NOiR] Hardening System Kernel...${NC}"
    
    # Kernel security settings
    echo -e "${BLUE}[*] Applying kernel-level protections...${NC}"
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null
    sysctl -w net.ipv4.conf.all.send_redirects=0 2>/dev/null
    sysctl -w net.ipv4.conf.default.send_redirects=0 2>/dev/null
    sysctl -w net.ipv4.conf.all.accept_redirects=0 2>/dev/null
    sysctl -w net.ipv4.conf.default.accept_redirects=0 2>/dev/null
    sysctl -w net.ipv4.conf.all.accept_source_route=0 2>/dev/null
    sysctl -w net.ipv4.conf.default.accept_source_route=0 2>/dev/null
    sysctl -w net.ipv4.conf.all.log_martians=1 2>/dev/null
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 2>/dev/null
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 2>/dev/null
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
    sysctl -w kernel.kptr_restrict=2 2>/dev/null
    sysctl -w kernel.dmesg_restrict=1 2>/dev/null
    sysctl -w kernel.yama.ptrace_scope=1 2>/dev/null
    sysctl -w dev.tty.ldisc_autoload=0 2>/dev/null
    sysctl -w fs.suid_dumpable=0 2>/dev/null
    
    # Make changes permanent
    cat > /etc/sysctl.d/99-virus-noir.conf << 'EOF'
# ViRUS NOiR Kernel Hardening
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1
dev.tty.ldisc_autoload=0
fs.suid_dumpable=0
EOF
    
    echo -e "${GREEN}[+] Kernel hardening complete${NC}"
}

# Advanced Firewall Configuration
configure_firewall() {
    echo -e "\n${CYAN}[ViRUS NOiR] Configuring Royal Firewall...${NC}"
    
    # Flush existing rules
    iptables -F
    iptables -X
    ip6tables -F
    ip6tables -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (with rate limiting)
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Block common attack vectors
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP  # NULL packets
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP   # XMAS packets
    iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 1/s -j ACCEPT  # Limit ping
    
    # Anti-DDoS measures
    iptables -N PORTSCAN
    iptables -A PORTSCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j RETURN
    iptables -A PORTSCAN -j DROP
    
    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    echo -e "${GREEN}[+] Royal Firewall configured${NC}"
}

# Malware Detection and Removal
malware_hunter() {
    echo -e "\n${CYAN}[ViRUS NOiR] Hunting Malware and Spyware...${NC}"
    
    # Update malware databases
    echo -e "${BLUE}[*] Updating threat databases...${NC}"
    apt update > /dev/null 2>&1
    
    # Install and update security tools
    if ! command -v rkhunter > /dev/null; then
        echo -e "${YELLOW}[*] Installing security tools...${NC}"
        apt install -y rkhunter chkrootkit clamav lynis > /dev/null 2>&1
    fi
    
    # Scan for rootkits
    echo -e "${BLUE}[*] Scanning for rootkits...${NC}"
    rkhunter --update
    rkhunter --check --sk --rwo >> "$THREAT_LOG"
    
    # Additional rootkit scan
    if command -v chkrootkit > /dev/null; then
        echo -e "${BLUE}[*] Running chkrootkit scan...${NC}"
        chkrootkit >> "$THREAT_LOG"
    fi
    
    # ClamAV scan
    if command -v clamscan > /dev/null; then
        echo -e "${BLUE}[*] Updating ClamAV definitions...${NC}"
        freshclam > /dev/null 2>&1
        echo -e "${BLUE}[*] Scanning for viruses...${NC}"
        clamscan -r /home /etc /var --infected --remove=yes >> "$THREAT_LOG"
    fi
    
    # Suspicious process detection
    echo -e "${BLUE}[*] Analyzing running processes...${NC}"
    ps aux | awk '{print $2, $11}' | while read pid cmd; do
        if [[ "$cmd" =~ (xmrig|minerd|cpuminer|nc|netcat|socat|backdoor) ]]; then
            echo "SUSPICIOUS PROCESS: $pid $cmd" | sudo tee -a "$THREAT_LOG"
            sudo kill -9 "$pid" 2>/dev/null && echo "Killed suspicious process: $cmd" | sudo tee -a "$LOG_FILE"
        fi
    done
    
    # Check for suspicious cron jobs
    echo -e "${BLUE}[*] Checking scheduled tasks...${NC}"
    crontab -l 2>/dev/null | grep -E '(wget|curl|bash|sh)\s*\|' | while read line; do
        echo "SUSPICIOUS CRON: $line" | sudo tee -a "$THREAT_LOG"
    done
    
    echo -e "${GREEN}[+] Malware hunt completed${NC}"
}

# Intrusion Detection System
setup_ids() {
    echo -e "\n${CYAN}[ViRUS NOiR] Deploying Intrusion Detection...${NC}"
    
    # Install and configure fail2ban
    if ! command -v fail2ban-server > /dev/null; then
        echo -e "${YELLOW}[*] Installing fail2ban...${NC}"
        apt install -y fail2ban > /dev/null 2>&1
    fi
    
    # Configure aggressive fail2ban
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/*error.log
EOF
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # File integrity monitoring
    echo -e "${BLUE}[*] Setting up file integrity monitoring...${NC}"
    if ! command -v aide > /dev/null; then
        apt install -y aide > /dev/null 2>&1
    fi
    aideinit -y
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    echo -e "${GREEN}[+] Intrusion Detection System deployed${NC}"
}

# Advanced Threat Prevention
threat_prevention() {
    echo -e "\n${CYAN}[ViRUS NOiR] Activating Threat Prevention...${NC}"
    
    # Secure shared memory
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab
    
    # Disable unnecessary services
    echo -e "${BLUE}[*] Securing system services...${NC}"
    systemctl stop bluetooth 2>/dev/null
    systemctl disable bluetooth 2>/dev/null
    systemctl stop cups 2>/dev/null
    systemctl disable cups 2>/dev/null
    systemctl stop avahi-daemon 2>/dev/null
    systemctl disable avahi-daemon 2>/dev/null
    
    # Secure SSH
    echo -e "${BLUE}[*] Hardening SSH...${NC}"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    sed -i 's/#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
    echo "AllowUsers $(whoami)" | sudo tee -a /etc/ssh/sshd_config
    systemctl restart ssh
    
    echo -e "${GREEN}[+] Threat prevention activated${NC}"
}

# Network Security
secure_network() {
    echo -e "\n${CYAN}[ViRUS NOiR] Fortifying Network...${NC}"
    
    # DNS security
    echo -e "${BLUE}[*] Configuring secure DNS...${NC}"
    echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf > /dev/null
    echo 'nameserver 1.0.0.1' | sudo tee -a /etc/resolv.conf > /dev/null
    echo 'nameserver 9.9.9.9' | sudo tee -a /etc/resolv.conf > /dev/null
    
    # ARP protection
    echo -e "${BLUE}[*] Configuring ARP security...${NC}"
    echo "net.ipv4.conf.all.arp_ignore = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.conf.all.arp_announce = 2" | sudo tee -a /etc/sysctl.conf > /dev/null
    
    # TCP hardening
    echo -e "${BLUE}[*] Hardening TCP stack...${NC}"
    echo "net.ipv4.tcp_rfc1337 = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
    echo "net.ipv4.tcp_max_syn_backlog = 2048" | sudo tee -a /etc/sysctl.conf > /dev/null
    
    sysctl -p > /dev/null 2>&1
    
    echo -e "${GREEN}[+] Network fortification complete${NC}"
}

# Real-time Monitoring
start_monitoring() {
    echo -e "\n${CYAN}[ViRUS NOiR] Starting Real-time Monitoring...${NC}"
    
    # Create monitoring script
    sudo tee /usr/local/bin/noir_monitor.sh > /dev/null << 'EOF'
#!/bin/bash
while true; do
    # Monitor network connections
    netstat -tunap 2>/dev/null | grep -E '(ESTABLISHED|LISTEN)' | while read conn; do
        if [[ "$conn" =~ \.(onion|tor) ]] || [[ "$conn" =~ (185\.|45\.) ]]; then
            echo "$(date): SUSPICIOUS CONNECTION: $conn" >> /var/log/noir_threats.log
        fi
    done
    
    # Monitor process creation
    ps aux --sort=-%cpu | head -10 | while read line; do
        if [[ "$line" =~ (miner|xmrig|cpuminer) ]]; then
            echo "$(date): CRYPTOMINER DETECTED: $line" >> /var/log/noir_threats.log
        fi
    done
    
    sleep 30
done
EOF
    
    sudo chmod +x /usr/local/bin/noir_monitor.sh
    nohup /usr/local/bin/noir_monitor.sh > /dev/null 2>&1 &
    
    echo -e "${GREEN}[+] Real-time monitoring activated${NC}"
}

# Emergency Lockdown
emergency_lockdown() {
    echo -e "\n${RED}[ViRUS NOiR] EMERGENCY LOCKDOWN ACTIVATED!${NC}"
    echo -e "${RED}[!] THIS WILL DISABLE ALL NON-ESSENTIAL SERVICES${NC}"
    
    read -p "Are you sure you want to continue? (yes/NO): " confirmation
    if [[ "$confirmation" != "yes" ]]; then
        echo -e "${YELLOW}[*] Lockdown cancelled${NC}"
        return
    fi
    
    # Block all incoming traffic
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    
    # Kill all unknown network connections
    netstat -tunap 2>/dev/null | grep ESTABLISHED | awk '{print $7}' | cut -d'/' -f1 | while read pid; do
        if [[ ! "$pid" =~ ^(1|$$)$ ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
            sudo kill -9 "$pid" 2>/dev/null
        fi
    done
    
    # Disable all user accounts except current
    sudo passwd -l root
    getent passwd | cut -d: -f1 | grep -v "$(whoami)" | while read user; do
        sudo passwd -l "$user" 2>/dev/null
    done
    
    # Shutdown non-critical services
    systemctl list-units --type=service --state=running | awk '{print $1}' | \
    grep -vE '(ssh|systemd|network|fail2ban)' | while read service; do
        sudo systemctl stop "$service" 2>/dev/null
    done
    
    echo -e "${GREEN}[+] System locked down${NC}"
}

# Security Audit
security_audit() {
    echo -e "\n${CYAN}[ViRUS NOiR] Performing Security Audit...${NC}"
    
    # Install and run Lynis
    if command -v lynis > /dev/null; then
        echo -e "${BLUE}[*] Running Lynis security audit...${NC}"
        lynis audit system --quick
    else
        echo -e "${YELLOW}[*] Lynis not installed, running basic audit...${NC}"
    fi
    
    # Check for open ports
    echo -e "${BLUE}[*] Scanning for open ports...${NC}"
    netstat -tunlp
    
    # Check user accounts
    echo -e "${BLUE}[*] Auditing user accounts...${NC}"
    awk -F: '($3 == 0) {print}' /etc/passwd
    
    # Check sudo privileges
    echo -e "${BLUE}[*] Checking sudo access...${NC}"
    getent group sudo | cut -d: -f4
    
    # File permissions audit
    echo -e "${BLUE}[*] Checking file permissions...${NC}"
    find / -perm -4000 -type f 2>/dev/null | head -20
    
    echo -e "${GREEN}[+] Security audit completed${NC}"
}

# Show status
show_status() {
    echo -e "\n${CYAN}[ViRUS NOiR] System Status${NC}"
    
    # Firewall status
    if iptables -L INPUT | grep -q "DROP"; then
        echo -e "${GREEN}[+] Firewall: ACTIVE${NC}"
    else
        echo -e "${RED}[+] Firewall: INACTIVE${NC}"
    fi
    
    # Fail2ban status
    if systemctl is-active fail2ban &> /dev/null; then
        echo -e "${GREEN}[+] Intrusion Detection: ACTIVE${NC}"
    else
        echo -e "${RED}[+] Intrusion Detection: INACTIVE${NC}"
    fi
    
    # Recent threats
    local recent_threats=$(sudo grep -c "SUSPICIOUS" "$THREAT_LOG" 2>/dev/null || echo "0")
    echo -e "${YELLOW}[+] Recent threats detected: $recent_threats${NC}"
}

# Main menu
main_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}1) Full System Fortification (Recommended)"
        echo "2) Malware Hunter & Cleaner"
        echo "3) Network Security Fortress"
        echo "4) Intrusion Detection System"
        echo "5) Real-time Threat Monitoring"
        echo "6) Security Audit & Assessment"
        echo "7) Emergency Lockdown"
        echo "8) System Status"
        echo "9) View Threat Logs"
        echo "10) Exit ViRUS NOiR"
        echo ""
        read -p "Select option [1-10]: " choice

        case $choice in
            1)
                harden_system
                configure_firewall
                threat_prevention
                secure_network
                setup_ids
                ;;
            2)
                malware_hunter
                ;;
            3)
                configure_firewall
                secure_network
                ;;
            4)
                setup_ids
                ;;
            5)
                start_monitoring
                ;;
            6)
                security_audit
                ;;
            7)
                emergency_lockdown
                ;;
            8)
                show_status
                ;;
            9)
                echo -e "\n${CYAN}Threat Log:${NC}"
                sudo tail -20 "$THREAT_LOG"
                ;;
            10)
                echo -e "${GREEN}[+] ViRUS NOiR - The King protects your system!${NC}"
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
        malware_hunter
        exit 0
        ;;
    --audit)
        security_audit
        exit 0
        ;;
    --monitor)
        start_monitoring
        exit 0
        ;;
    --help)
        show_banner
        echo -e "${WHITE}Usage: $0 [OPTION]${NC}"
        echo ""
        echo "Options:"
        echo "  --status    Show current protection status"
        echo "  --scan      Run malware scan"
        echo "  --audit     Perform security audit"
        echo "  --monitor   Start real-time monitoring"
        echo "  --help      Show this help message"
        echo ""
        echo "Without options: Start interactive menu"
        exit 0
        ;;
esac

# Initialize and start
check_privileges
init_logs

# Signal trap for cleanup
trap 'echo -e "\n${RED}[!] ViRUS NOiR interrupted${NC}"; exit 1' INT TERM

# Start main menu
main_menu
