#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

#Add some basic function here
function LOGD() {
    echo -e "${yellow}[DEG] $* ${plain}"
}

function LOGE() {
    echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
    echo -e "${green}[INF] $* ${plain}"
}
# check root
[[ $EUID -ne 0 ]] && LOGE "ERROR ! You Must Grant Administrator Access for this Action to take place \n" && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed To check the OS Version / Name ! " >&2
    exit 1
fi

echo "The OS release is: $release"


os_version=""
os_version=$(grep -i version_id /etc/os-release | cut -d \" -f2 | cut -d . -f1)

if [[ "${release}" == "centos" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red} Please Use CentOS 8 Or Higher Versions ! ${plain}\n" && exit 1
    fi
elif [[ "${release}" ==  "ubuntu" ]]; then
    if [[ ${os_version} -lt 20 ]]; then
        echo -e "${red}Please Use Ubuntu 20 Or Higher Versions Available ! ${plain}\n" && exit 1
    fi

elif [[ "${release}" == "fedora" ]]; then
    if [[ ${os_version} -lt 36 ]]; then
        echo -e "${red}Please Use Fedora 36 or Higher Versions Available ! ${plain}\n" && exit 1
    fi

elif [[ "${release}" == "debian" ]]; then
    if [[ ${os_version} -lt 10 ]]; then
        echo -e "${red} Please use Debian 10 or higher Versions Available ! ${plain}\n" && exit 1
    fi
fi


confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [Default$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "${red} Restart The Panel to take effect , NOTE: This action will restart the Xray TOO ! ->  ${plain}" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${green}Press Enter to return to menu :  ${plain}" && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/Anonymotrix/3x-ui/main/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    confirm "This function will forcefully reinstall the latest version, and the data will not be lost. Do you want to continue?" "n"
    if [[ $? != 0 ]]; then
        LOGE "Cancelled"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi
    bash <(curl -Ls https://raw.githubusercontent.com/Anonymotrix/3x-ui/main/install.sh)
    if [[ $? == 0 ]]; then
        LOGI "Update is complete, Panel has automatically restarted "
        exit 0
    fi
}

uninstall() {
    confirm "Are you sure you want to uninstall the panel? xray will also uninstalled!" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    systemctl stop x-ui
    systemctl disable x-ui
    rm /etc/systemd/system/x-ui.service -f
    systemctl daemon-reload
    systemctl reset-failed
    rm /etc/x-ui/ -rf
    rm /usr/local/x-ui/ -rf

    echo ""
    echo -e "Uninstalled Successfully，If you want to remove this script，then after exiting the script run ${green}rm /usr/bin/x-ui -f${plain} to delete it."
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

reset_user() {
    confirm "Reset your username and password to admin?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    /usr/local/x-ui/x-ui setting -username admin -password admin
    echo -e "Username and password have been reset to ${green}admin${plain}，Please restart the panel now."
    confirm_restart
}

reset_config() {
    confirm "Are you sure you want to reset all panel settings，Account data will not be lost，Username and password will not change" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    /usr/local/x-ui/x-ui setting -reset
    echo -e "All panel settings have been reset to default，Please restart the panel now，and use the default ${green}2053${plain} Port to Access the web Panel"
    confirm_restart
}

check_config() {
    info=$(/usr/local/x-ui/x-ui setting -show true)
    if [[ $? != 0 ]]; then
        LOGE "get current settings error,please check logs"
        show_menu
    fi
    LOGI "${info}"
}

set_port() {
    echo && echo -n -e "Enter port number[1-65535]: " && read port
    if [[ -z "${port}" ]]; then
        LOGD "Cancelled"
        before_show_menu
    else
        /usr/local/x-ui/x-ui setting -port ${port}
        echo -e "The port is set，Please restart the panel now，and use the new port ${green}${port}${plain} to access web panel"
        confirm_restart
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        LOGI "Panel is running，No need to start again，If you need to restart, please select restart"
    else
        systemctl start x-ui
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            LOGI "x-ui Started Successfully"
        else
            LOGE "panel Failed to start，Probably because it takes longer than two seconds to start，Please check the log information later"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    check_status
    if [[ $? == 1 ]]; then
        echo ""
        LOGI "Panel stopped，No need to stop again!"
    else
        systemctl stop x-ui
        sleep 2
        check_status
        if [[ $? == 1 ]]; then
            LOGI "x-ui and xray stopped successfully"
        else
            LOGE "Panel stop failed，Probably because the stop time exceeds two seconds，Please check the log information later"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    systemctl restart x-ui
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        LOGI "x-ui and xray Restarted successfully"
    else
        LOGE "Panel restart failed，Probably because it takes longer than two seconds to start，Please check the log information later"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    systemctl status x-ui -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    systemctl enable x-ui
    if [[ $? == 0 ]]; then
        LOGI "x-ui Set to boot automatically on startup successfully"
    else
        LOGE "x-ui Failed to set Autostart"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    systemctl disable x-ui
    if [[ $? == 0 ]]; then
        LOGI "x-ui Autostart Cancelled successfully"
    else
        LOGE "x-ui Failed to cancel autostart"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    journalctl -u x-ui.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable_bbr() {

if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf && grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
  echo -e "${green}BBR is already enabled!${plain}"
  exit 0
fi

# Check the OS and install necessary packages
if [[ "$(cat /etc/os-release | grep -E '^ID=' | awk -F '=' '{print $2}')" == "ubuntu" ]]; then
  sudo apt-get update && sudo apt-get install -yqq --no-install-recommends ca-certificates
elif [[ "$(cat /etc/os-release | grep -E '^ID=' | awk -F '=' '{print $2}')" == "debian" ]]; then
  sudo apt-get update && sudo apt-get install -yqq --no-install-recommends ca-certificates
elif [[ "$(cat /etc/os-release | grep -E '^ID=' | awk -F '=' '{print $2}')" == "fedora" ]]; then
  sudo dnf -y update && sudo dnf -y install ca-certificates
elif [[ "$(cat /etc/os-release | grep -E '^ID=' | awk -F '=' '{print $2}')" == "centos" ]]; then
  sudo yum -y update && sudo yum -y install ca-certificates
else
  echo "Unsupported operating system. Please check the script and install the necessary packages manually."
  exit 1
fi

# Enable BBR
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf

# Apply changes
sudo sysctl -p

# Verify that BBR is enabled
if [[ $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}') == "bbr" ]]; then
  echo -e "${green}BBR has been enabled successfully.${plain}"
else
  echo -e "${red}Failed to enable BBR. Please check your system configuration.${plain}"
fi

}

update_shell() {
    wget -O /usr/bin/x-ui -N --no-check-certificate https://github.com/Anonymotrix/3x-ui/raw/main/x-ui.sh
    if [[ $? != 0 ]]; then
        echo ""
        LOGE "Failed to download script，Please check whether the machine can connect Github"
        before_show_menu
    else
        chmod +x /usr/bin/x-ui
        LOGI "Upgrade script succeeded，Please rerun the script" && exit 0
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/x-ui.service ]]; then
        return 2
    fi
    temp=$(systemctl status x-ui | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

check_enabled() {
    temp=$(systemctl is-enabled x-ui)
    if [[ x"${temp}" == x"enabled" ]]; then
        return 0
    else
        return 1
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        LOGE "Panel installed，Please do not reinstall"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        LOGE "Please install the panel first"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
    0)
        echo -e "Panel state: ${green}Running${plain}"
        show_enable_status
        ;;
    1)
        echo -e "Panel state: ${yellow}Not Running${plain}"
        show_enable_status
        ;;
    2)
        echo -e "Panel state: ${red}Not Installed${plain}"
        ;;
    esac
    show_xray_status
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Start automatically: ${green}Yes${plain}"
    else
        echo -e "Start automatically: ${red}No${plain}"
    fi
}

check_xray_status() {
    count=$(ps -ef | grep "xray-linux" | grep -v "grep" | wc -l)
    if [[ count -ne 0 ]]; then
        return 0
    else
        return 1
    fi
}

show_xray_status() {
    check_xray_status
    if [[ $? == 0 ]]; then
        echo -e "xray state: ${green}Running${plain}"
    else
        echo -e "xray state: ${red}Not Running${plain}"
    fi
}

#this will be an entrance for ssl cert issue
#here we can provide two different methods to issue cert
#first.standalone mode second.DNS API mode
ssl_cert_issue() {
    local method=""
    echo -E ""
    LOGD "********Usage********"
    LOGI "this shell script will use acme to help issue certs."
    LOGI "here we provide two methods for issuing certs:"
    LOGI "method 1:acme standalone mode,need to keep port:80 open"
    LOGI "method 2:acme DNS API mode,need provide Cloudflare Global API Key"
    LOGI "recommend method 2 first,if it fails,you can try method 1."
    LOGI "certs will be installed in /root/cert directory"
    read -p "please choose which method do you want,type 1 or 2": method
    LOGI "you choosed method:${method}"

    if [ "${method}" == "1" ]; then
        ssl_cert_issue_standalone
    elif [ "${method}" == "2" ]; then
        ssl_cert_issue_by_cloudflare
    else
        LOGE "invalid input,please check it..."
        exit 1
    fi
}

open_ports() {

  # Check if the firewall is inactive
  if sudo ufw status | grep -q "Status: active"; then
    echo "firewall is already active"
  else
    # Open the necessary ports
    sudo ufw allow ssh
    sudo ufw allow http
    sudo ufw allow https
    sudo ufw allow 2053/tcp

    # Enable the firewall
    sudo ufw --force enable
  fi

  # Prompt the user to enter a list of ports
  read -p "Enter the ports you want to open (e.g. 80,443,2053 or range 400-500): " ports

  # Check if the input is valid
  if ! [[ $ports =~ ^([0-9]+|[0-9]+-[0-9]+)(,([0-9]+|[0-9]+-[0-9]+))*$ ]]; then
     echo "Error: Invalid input. Please enter a comma-separated list of ports or a range of ports (e.g. 80,443,2053 or 400-500)." >&2; exit 1
  fi

  # Open the specified ports using ufw
  IFS=',' read -ra PORT_LIST <<< "$ports"
  for port in "${PORT_LIST[@]}"; do
    if [[ $port == *-* ]]; then
      # Split the range into start and end ports
      start_port=$(echo $port | cut -d'-' -f1)
      end_port=$(echo $port | cut -d'-' -f2)
      # Loop through the range and open each port
      for ((i=start_port; i<=end_port; i++)); do
        sudo ufw allow $i
      done
    else
      sudo ufw allow "$port"
    fi
  done

  # Confirm that the ports are open
  sudo ufw status | grep $ports
}



update_geo(){
    systemctl stop x-ui
    cd /usr/local/x-ui/bin
    rm -f geoip.dat geosite.dat iran.dat
    wget -N https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    wget -N https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    wget -N https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat
    systemctl start x-ui
    echo -e "${green}Geosite and Geoip have been updated successfully!${plain}"
before_show_menu
}

install_acme() {
    cd ~
    LOGI "install acme..."
    curl https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        LOGE "install acme failed"
        return 1
    else
        LOGI "install acme succeed"
    fi
    return 0
}

#method for standalone mode
ssl_cert_issue_standalone() {
    #check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "acme.sh could not be found. we will install it"
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "install acme failed, please check logs"
            exit 1
        fi
    fi
    #install socat second
    if [[ x"${release}" == x"centos" ]]; then
        yum install socat -y
    else
        apt install socat -y
    fi
    if [ $? -ne 0 ]; then
        LOGE "install socat failed,please check logs"
        exit 1
    else
        LOGI "install socat succeed..."
    fi

    #get the domain here,and we need verify it
    local domain=""
    read -p "please input your domain:" domain
    LOGD "your domain is:${domain},check it..."
    #here we need to judge whether there exists cert already
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
    if [ ${currentCert} == ${domain} ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        LOGE "system already have certs here,can not issue again,current certs details:"
        LOGI "$certInfo"
        exit 1
    else
        LOGI "your domain is ready for issuing cert now..."
    fi
	
	#create a directory for install cert
	certPath="/root/cert/${domain}"
	if [ ! -d "$certPath" ]; then
		mkdir -p "$certPath"
	else
		rm -rf "$certPath"
		mkdir -p "$certPath"
	fi
	
    #get needed port here
    local WebPort=80
    read -p "please choose which port do you use,default will be 80 port:" WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        LOGE "your input ${WebPort} is invalid,will use default port"
    fi
    LOGI "will use port:${WebPort} to issue certs,please make sure this port is open..."
    #NOTE:This should be handled by user
    #open the port and kill the occupied progress
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone --httpport ${WebPort}
    if [ $? -ne 0 ]; then
        LOGE "issue certs failed,please check logs"
        rm -rf ~/.acme.sh/${domain}
        exit 1
    else
        LOGE "issue certs succeed,installing certs..."
    fi
    #install cert
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem

    if [ $? -ne 0 ]; then
        LOGE "install certs failed,exit"
        rm -rf ~/.acme.sh/${domain}
        exit 1
    else
        LOGI "install certs succeed,enable auto renew..."
    fi
	
	~/.acme.sh/acme.sh --upgrade --auto-upgrade
	if [ $? -ne 0 ]; then
		LOGE "auto renew failed, certs details:"
		ls -lah cert/*
		chmod 755 $certPath/*
		exit 1
	else
		LOGI "auto renew succeed, certs details:"
		ls -lah cert/*
		chmod 755 $certPath/*
	fi

}

#method for DNS API mode
ssl_cert_issue_by_cloudflare() {
    echo -E ""
    LOGD "---- THINGS THAT ARE REQUIRED FOR APPLING FOR A CERTIFICATE ----"
    LOGI "1.Need a registered Cloudflare Email"
    LOGI "2.Need Cloudflare Global API Key"
    LOGI "3.Your domain use Cloudflare as resolver"
    confirm "I have confirmed all these info above[y/n]" "y"
    if [ $? -eq 0 ]; then
        install_acme
        if [ $? -ne 0 ]; then
            LOGE "install acme failed,please check logs"
            exit 1
        fi
        CF_Domain=""
        CF_GlobalKey=""
        CF_AccountEmail=""
        
        LOGD "Please Input Your Domain For Generating The Certificate"
        read -p "Input Your Domain In here ! " CF_Domain
        LOGD "Your Domain is :${CF_Domain},check it..."
        #here we need to judge whether there exists cert already
        local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
        if [ ${currentCert} == ${CF_Domain} ]; then
            local certInfo=$(~/.acme.sh/acme.sh --list)
            LOGE "system already have certs here,can not issue again,current certs details:"
            LOGI "$certInfo"
            exit 1
        else
            LOGI "Your Domain is ready for getting a Certificate !"
        fi
		
		#create a directory for install cert
		certPath="/root/cert/${CF_Domain}"
		if [ ! -d "$certPath" ]; then
			mkdir -p "$certPath"
		else
			rm -rf "$certPath"
			mkdir -p "$certPath"
		fi
	
        LOGD "Please Input Your Cloudflare API KEY :"
        read -p "KEY : " CF_GlobalKey
        LOGD "Your CloudFlare Global Key Is : -> ${CF_GlobalKey}"
        LOGD "Please Input Your CloudFlare Email : "
        read -p "Input Your Email in Here : " CF_AccountEmail
        LOGD "Your CloudFlare Email IS :${CF_AccountEmail}"
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        if [ $? -ne 0 ]; then
            LOGE "change the default CA to Lets'Encrypt failed,exit"
            exit 1
        fi
        export CF_Key="${CF_GlobalKey}"
        export CF_Email=${CF_AccountEmail}
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${CF_Domain} -d *.${CF_Domain} --log
        if [ $? -ne 0 ]; then
            LOGE "issue cert failed,exit"
            rm -rf ~/.acme.sh/${CF_Domain}
            exit 1
		else
			LOGI "Certificate issued Successfully, Installing..."
		fi
		~/.acme.sh/acme.sh --installcert -d ${CF_Domain} -d *.${CF_Domain} \
			--key-file /root/cert/${CF_Domain}/privkey.pem \
			--fullchain-file /root/cert/${CF_Domain}/fullchain.pem

		if [ $? -ne 0 ]; then
			LOGE "install cert failed,exit"
			rm -rf ~/.acme.sh/${CF_Domain}
			exit 1
		else
			LOGI "Certificate installed Successfully,Turning on automatic updates..."
		fi
		~/.acme.sh/acme.sh --upgrade --auto-upgrade
		if [ $? -ne 0 ]; then
			LOGE "auto renew failed, certs details:"
			ls -lah cert/*
			chmod 755 $certPath/*
			exit 1
		else
			LOGI "auto renew succeed, certs details:"
			ls -lah cert/*
			chmod 755 $certPath/*
		fi
    else
        show_menu
    fi
}
google_recaptcha() {
  curl -O https://raw.githubusercontent.com/jinwyp/one_click_script/master/install_kernel.sh && chmod +x ./install_kernel.sh && ./install_kernel.sh
  echo ""
  before_show_menu
}

run_speedtest() {
    # Check if Speedtest is already installed
    if ! command -v speedtest &> /dev/null; then
        # If not installed, install it
        if command -v dnf &> /dev/null; then
            sudo dnf install -y curl
            curl -s https://install.speedtest.net/app/cli/install.rpm.sh | sudo bash
            sudo dnf install -y speedtest
        elif command -v yum &> /dev/null; then
            sudo yum install -y curl
            curl -s https://install.speedtest.net/app/cli/install.rpm.sh | sudo bash
            sudo yum install -y speedtest
        elif command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y curl
            curl -s https://install.speedtest.net/app/cli/install.deb.sh | sudo bash
            sudo apt-get install -y speedtest
        elif command -v apt &> /dev/null; then
            sudo apt update && sudo apt install -y curl
            curl -s https://install.speedtest.net/app/cli/install.deb.sh | sudo bash
            sudo apt install -y speedtest
        else
            echo "Error: Package manager not found. You may need to install Speedtest manually."
            return 1
        fi
    fi

    # Run Speedtest
    speedtest
}



show_usage() {
    echo "x-ui control menu usages: "
    echo "----------------- MHSenai X Anonymotrix -------------------------"
    echo -e "x-ui              - Show the control Menu | ( The Adminstrator Menu )"
    echo -e "x-ui start        - Start X-UI | Xray "
    echo -e "x-ui stop         - Stop X-UI | Xray "
    echo -e "x-ui restart      - Restart X-UI | Xray "
    echo -e "x-ui status       - Show x-ui Current Status "
    echo -e "x-ui enable       - Enable X-UI , Xray on Syatem Default Startup"
    echo -e "x-ui disable      - Disable X-UI , Xray on Syatem Default Startup"
    echo -e "x-ui log          - Check X-UI Logs"
    echo -e "x-ui update       - Update X-UI to the latest Version Available ! "
    echo -e "x-ui install      - Install X-UI  "
    echo -e "x-ui uninstall    - Uninstall X-UI "
    echo "------------------ MHSenai X Anonymotrix ------------------------"
}

show_menu() {
    echo -e "
  ${green}3X-ui Panel Management Script${plain}
  ${green}0.${plain} Exit Script
————————————————
  ${green}1.${plain} Install x-ui
  ${green}2.${plain} Update X-UI to the latest Version Available !
  ${green}3.${plain} Uninstall X-UI
————————————————
  ${green}4.${plain} Reset The Username and Password To ( admin , admin ) 
  ${green}5.${plain} Reset Panel Current Settings ( This Action may be Dangerous )
  ${green}6.${plain} Change The Panel Port [ 1 , 65500 ] 
  ${green}7.${plain} View Current Panel Settings ( PORT , USERNAME , PASSWORD and etc... ) 
————————————————
  ${green}8.${plain} Start X-UI | Xray
  ${green}9.${plain} Stop X-UI | Xray
  ${green}10.${plain} Restart X-UI | Xray
  ${green}11.${plain} Check X-UI current status
  ${green}12.${plain} Check X-UI Logs
————————————————
  ${green}13.${plain} Enable X-UI , Xray on Syatem Default Startup
  ${green}14.${plain} Disable X-UI , Xray on Syatem Default Startup
————————————————
  ${green}15.${plain} Enable BBR 
  ${green}16.${plain} Apply for an SSL Certificate 
  ${green}17.${plain} Update Geographical Files
  ${green}18.${plain} Active Firewall and the ports that are open
  ${green}19.${plain} Fixing Google reCAPTCHA | Disabling It
  ${green}20.${plain} SPEEDTEST ! ( POWERED BY OKALA ) 
 "
    show_status
    echo && read -p "Please Enter Your Desired Selection Between The Ranges Of : [0-20]: " num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        check_uninstall && install
        ;;
    2)
        check_install && update
        ;;
    3)
        check_install && uninstall
        ;;
    4)
        check_install && reset_user
        ;;
    5)
        check_install && reset_config
        ;;
    6)
        check_install && set_port
        ;;
    7)
        check_install && check_config
        ;;
    8)
        check_install && start
        ;;
    9)
        check_install && stop
        ;;
    10)
        check_install && restart
        ;;
    11)
        check_install && status
        ;;
    12)
        check_install && show_log
        ;;
    13)
        check_install && enable
        ;;
    14)
        check_install && disable
        ;;
    15)
        enable_bbr
        ;;
    16)
        ssl_cert_issue
        ;;
    17)
        update_geo
        ;;
    18)
        open_ports
        ;;
    19)
        google_recaptcha
        ;;
	20)
        run_speedtest
        ;;
    *)
        LOGE "Please enter the correct number [0-20]"
        ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
    "start")
        check_install 0 && start 0
        ;;
    "stop")
        check_install 0 && stop 0
        ;;
    "restart")
        check_install 0 && restart 0
        ;;
    "status")
        check_install 0 && status 0
        ;;
    "enable")
        check_install 0 && enable 0
        ;;
    "disable")
        check_install 0 && disable 0
        ;;
    "log")
        check_install 0 && show_log 0
        ;;
    "update")
        check_install 0 && update 0
        ;;
    "install")
        check_uninstall 0 && install 0
        ;;
    "uninstall")
        check_install 0 && uninstall 0
        ;;
    *) show_usage ;;
    esac
else
    show_menu
fi
