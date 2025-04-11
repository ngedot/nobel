#!/bin/bash
### Color
# apt upgrade -y
# apt update -y
apt install lolcat -y
apt install wondershaper -y
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
WHITE='\033[0;37m'
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
TIMES="10"
# Telegram Bot Configuration
CHATID=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 3)
KEY=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 2)
URL="https://api.telegram.org/bot$KEY/sendMessage"
  # // Exporint IP AddressInformation
export IP=$( curl -s https://ipinfo.io/ip/?token=22bdf1094ea479 )

# // Clear Data
clear

  # // Banner
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "  Welcome To SCRIPT ${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e " This Will Quick Setup VPN Server On Your Server"
echo -e "  Author : ${green} ServerPremiumVIP ® ${NC}${YELLOW}(${NC} ${green} ErfanRInanda ${NC}${YELLOW})${NC}"
echo -e " © https://t.me/ServerPremiumVIP${YELLOW}(${NC} 2023 ${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2
###### IZIN SC 

# // Checking Os Architecture
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# // Checking System
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
    exit 1
fi

# // IP Address Validating
if [[ $IP == "" ]]; then
    echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successfull
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
#IZIN SCRIPT
MYIP=$(curl -s https://ipinfo.io/ip/?token=22bdf1094ea479 )
echo -e "\e[32mloading...\e[0m"
clear
#IZIN SCRIPT
MYIP=$(curl -s https://ipinfo.io/ip/?token=22bdf1094ea479 )
echo -e "\e[32mloading...\e[0m" 
clear
# Version sc
clear
#########################
# USERNAME
rm -f /usr/bin/user
username=$(curl -sS https://raw.githubusercontent.com/ngedot/botol/main/Aktivasi | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
# validity
rm -f /usr/bin/e
today=`date -d "0 days" +"%Y-%m-%d"`
valid=$(curl -sS https://raw.githubusercontent.com/ngedot/botol/main/Aktivasi | grep $MYIP | awk '{print $3}')
echo "$valid" >/usr/bin/e
# DETAIL ORDER
username=$(cat /usr/bin/user)
# oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear
# CERTIFICATE STATUS
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
# VPS Information
DATE=$(date +'%Y-%m-%d')
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""

# Status ExpiRED Active | Geo Project
Info="${GREEN}Active${NC}"
Error="${RED}Expired${NC}"
if [[ "$certifacate" -le "0" ]]; then
sts="${Error}"
echo -e " $BLUE╭──────────────────────────────────────────────────────────╮${NC}"
echo -e " $BLUE│$NC$RED    IP address not authorized by admin $NC"
echo -e " $BLUE│$NC$RED    Please contact admin to rent this script $NC"
echo -e " $BLUE│$NC$r • $NC$WHITE Whatsapp :$NC $GREEN 62818776240$NC"
echo -e " $BLUE│$NC$r • $NC$WHITE Telegram :$NC $GREEN erfanrinanda$NC"
echo -e " $BLUE╰──────────────────────────────────────────────────────────╯${NC}"
sleep 3
exit 1
else
sts="${Info}"
fi
echo -e "\e[32mloading...\e[0m"
clear
# REPO    
    REPO="https://raw.githubusercontent.com/ngedot/botol/master/"

####
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
	echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
	echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
		echo -e "${green} =============================== ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
		echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

### Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}

# Buat direktori xray
print_install "Membuat direktori xray"
    mkdir -p /etc/xray
    wget https://raw.githubusercontent.com/ngedot/botol/main/Aktivasi -O /etc/xray/premium
    curl -s https://ipinfo.io/ip/?token=22bdf1094ea479 > /etc/xray/ipvps
    curl -s ipinfo.io/city?token=22bdf1094ea479 >>/etc/xray/city
    curl -s ipinfo.io/timezone?token=22bdf1094ea479 >>/etc/xray/timezone
    curl -s ipinfo.io/org?token=22bdf1094ea479 | cut -d " " -f 2-10 >>/etc/xray/isp
    touch /etc/xray/domain
    mkdir -p /var/log/xray
#    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    mkdir -p /var/lib/kyt >/dev/null 2>&1
    # // Ram Information
    while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
        mem_used="$((mem_used-=${b/kB}))"
    ;;
    esac
    done < /proc/meminfo
    Ram_Usage="$((mem_used / 1024))"
    Ram_Total="$((mem_total / 1024))"
    export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
    export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
    export Kernel=$( uname -r )
    export Arch=$( uname -m )
    export IP=$(curl -s https://ipinfo.io/ip/?token=22bdf1094ea479 )

# Function: First Setup
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    echo -e "${OK} Timezone and iptables-persistent configured"
}

# Function: Install HAProxy
function install_haproxy() {
    add-apt-repository ppa:vbernat/haproxy-3.0 -y
    apt update -y
    apt install -y haproxy=3.0.\*
    echo -e "${OK} HAProxy 3.0.\* installed"
}

# Function: Install Nginx
function install_nginx() {
    apt install -y nginx
    echo -e "${OK} Nginx installed"
}

# Function: Install Base Packages
function base_package() {
    apt update -y && apt upgrade -y
    apt install -y zip pwgen openssl socat cron bash-completion chrony ntpdate sudo \
        nginx vnstat netfilter-persistent iptables-persistent net-tools \
        build-essential gcc g++ python3 htop lsof tar wget curl ruby zip unzip \
        p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates \
        bsd-mailx gnupg gnupg2 lsb-release
    echo -e "${OK} Base packages installed"
}
clear
# Fungsi input domain
function pasang_domain() {
echo -e ""
clear
    echo -e "   .----------------------------------."
echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
echo -e "   '----------------------------------'"
echo -e "     \e[1;32m1)\e[0m Domain Sendiri"
echo -e "     \e[1;32m2)\e[0m Gunakan Domain Random Khusus Digital ocean ISP LAIN ✖️ "
echo -e "   ------------------------------------"
read -p "   Please select numbers 1-2 or Any Button(Random) : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mPlease Enter Your Subdomain $NC"
read -p "   Subdomain: " host1
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
#install cf
wget ${REPO}limit/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
    fi
}

clear
#GANTI PASSWORD DEFAULT
function restart_system() {
    USRSC=$(curl -sS https://raw.githubusercontent.com/ngedot/botol/main/Aktivasi | grep $MYIP | awk '{print $2}')
    EXPSC=$(curl -sS https://raw.githubusercontent.com/ngedot/botol/main/Aktivasi | grep $MYIP | awk '{print $3}')
    DATEVPS=$(date +'%d/%m/%Y')
    ISP=$(cat /etc/xray/isp)
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM⚡</b>
<code>────────────────────</code>
<code>Owner    :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$IPVPS</code>
<code>ISP      :</code><code>$ISP</code>
<code>DATE     :</code><code>$DATEVPS</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>────────────────────</code>
<b> SCRIPT NOTIF </b>
<code>────────────────────</code>
<i>Automatic Notifications From Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://wa.me/62818776240"}]]}' 
#"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ2","url":"https://wa.me/6287824016438"}]]}'
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

}
clear
# Function: Configure SSL
function configure_ssl() {
    domain=$(cat /root/domain)
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 600 /etc/xray/xray.key
    echo -e "${OK} SSL configured for domain $domain"
}

# Function: Restart Services
function restart_services() {
    systemctl restart nginx
    systemctl restart haproxy
    echo -e "${OK} Services restarted"
}

function install_script() {
    first_setup
    base_package
    install_haproxy
    install_nginx
    configure_ssl
    restart_services
    echo -e "${Green} Script successfully installed!${NC}"
}

function make_folder_xray() {
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/ssh
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
}
    
    # Settings UP Nginix Server
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}limit/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}limit/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}limit/nginx.conf > /etc/nginx/nginx.conf
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

function ssh(){
clear
print_install "Memasang Password SSH"
    wget -O /etc/pam.d/common-password "${REPO}limit/password"
chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}

function udp_mini(){
clear
print_install "Memasang Service Limit Quota"
wget raw.githubusercontent.com/ngedot/botol/master/limit/limit.sh && chmod +x limit.sh && ./limit.sh

cd
wget -q -O /usr/bin/limit-ip "${REPO}limit/limit-ip"
chmod +x /usr/bin/*
cd /usr/bin
sed -i 's/\r//' limit-ip
cd
clear

# // Installing UDP Mini
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}limit/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}limit/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}limit/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}limit/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "Limit Quota Service"
}

function ssh_slow(){
clear
# // Installing UDP Mini
print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}limit/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
 print_success "SlowDNS"
}

clear
function ins_SSHD(){
clear
print_install "Memasang SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}limit/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}

clear
function ins_dropbear() {
    clear
    print_install "Menginstall Dropbear"
    # Installing Dropbear
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}limit/dropbear.conf"
    chmod +x /etc/default/dropbear
    /etc/init.d/dropbear restart
    /etc/init.d/dropbear status
    systemctl enable vnstat
    /etc/init.d/vnstat restart
    /etc/init.d/vnstat status
    print_success "Dropbear"
}

clear

function ins_openvpn(){
clear
print_install "Menginstall OpenVPN"
#OpenVPN
wget ${REPO}limit/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}

# Fungsi untuk menginstal rclone
function install_rclone() {
    clear
    print_install "Menginstal Rclone"
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}limit/rclone.conf"
    print_success "Rclone berhasil diinstal"
}

# Fungsi untuk menginstal Wondershaper
function install_wondershaper() {
    clear
    print_install "Menginstal Wondershaper"
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper
    echo > /home/limit
    print_success "Wondershaper berhasil diinstal"
}

# Fungsi untuk menginstal msmtp
function install_msmtp() {
    clear
    print_install "Menginstal msmtp"
    apt install msmtp-mta ca-certificates bsd-mailx -y
    cat <<EOF >/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user serverkubackup@gmail.com
from serverkubackup@gmail.com
password serverkubackup 2023
logfile ~/.msmtp.log
EOF
    chown -R www-data:www-data /etc/msmtprc
    print_success "msmtp berhasil diinstal"
}

# Fungsi untuk menjalankan skrip ipserver
function run_ipserver() {
    clear
    print_install "Menjalankan skrip ipserver"
    wget -q -O /etc/ipserver "${REPO}limit/ipserver" && bash /etc/ipserver
    print_success "Skrip ipserver berhasil dijalankan"
}

# Fungsi utama untuk menginstal backup server
function ins_backup() {
    clear
    print_install "Memasang Backup Server"
    install_rclone
    install_wondershaper
    install_msmtp
    run_ipserver
    print_success "Backup Server berhasil dipasang"
}

# Fungsi untuk menginstal gotop
clear
function install_gotop() {
    clear
    echo "Memasang Gotop..."

    # Mendapatkan versi terbaru Gotop dari GitHub
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"

    # Mengunduh dan memasang Gotop
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Mengonfirmasi instalasi
    if dpkg -l | grep -q gotop; then
        echo "Gotop berhasil dipasang."
    else
        echo "Instalasi Gotop gagal."
        return 1
    fi

    # > Sinkronisasi jam
    echo "Sinkronisasi jam dengan NTP..."
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # > Mengaktifkan BBR
    echo "Mengaktifkan BBR..."
    wget ${REPO}limit/bbr.sh && chmod +x bbr.sh && ./bbr.sh
}

function ins_Fail2ban(){
clear
print_install "Menginstall Fail2ban"
apt -y install fail2ban > /dev/null 2>&1
sudo systemctl enable --now fail2ban
/etc/init.d/fail2ban restart
/etc/init.d/fail2ban status

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi

clear
# banner
echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

# Ganti Banner
wget -O /etc/kyt.txt "${REPO}limit/issue.net"
print_success "Fail2ban"
}

function ins_epro(){
clear
print_install "Menginstall ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}limit/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}limit/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}limit/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}limit/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# remove unnecessary files
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy"
}

function ins_restart(){
clear
print_install "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "All Packet"
}

#Instal Menu
function menu(){
    clear
    print_install "Memasang Menu Packet"
    wget ${REPO}limit/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/local/sbin/xp
	END
	cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/20 * * * * root /usr/local/sbin/clearlog
		END
    chmod 644 /root/.profile
	
    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END

    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
print_success "Menu Packet"

# Restart layanan after install
function enable_services(){
clear
print_install "Enable Service"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
    clear
}

# Fingsi Install Script
function instal(){
clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    # install_xray
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}
instal
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
#sudo hostnamectl set-hostname $user
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
echo -e "${green} Script Successfull Installed"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For Reboot") "
reboot