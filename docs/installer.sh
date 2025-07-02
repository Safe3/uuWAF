#!/bin/bash

# UUSEC WAF one click installation script
# Supported system: CentOS/RHEL 7+, Debian 11+, Ubuntu 18+, Fedora 32+, etc

info() {
    echo -e "\033[32m[UUSEC WAF] $*\033[0m"
}

warning() {
    echo -e "\033[33m[UUSEC WAF] $*\033[0m"
}

abort() {
    echo -e "\033[31m[UUSEC WAF] $*\033[0m"
    exit 1
}

if [[ $EUID -ne 0 ]]; then
    abort "This script must be run with root privileges"
fi

OS_ARCH=$(uname -m)
case "$OS_ARCH" in
    x86_64)
    ;;
    *)
    abort "Unsupported CPU arch: $OS_ARCH"
    ;;
esac

if [ -f /etc/os-release ]; then
    source /etc/os-release
    OS_NAME=$ID
    OS_VERSION=$VERSION_ID
elif type lsb_release >/dev/null 2>&1; then
    OS_NAME=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    OS_VERSION=$(lsb_release -sr)
else
    abort "Unable to detect operating system"
fi

check_ports() {
    if [ $(command -v ss) ]; then
        for port in 80 443 777 4443 4447 6612; do
            if ss -tln "( sport = :${port} )" | grep -q LISTEN; then
                abort "Port ${port} is occupied, please close it and try again"
            fi
        done
	fi
}

install_waf() {
    if [ ! $(command -v curl) ]; then
		$( command -v yum || command -v apt-get || command -v zypper ) -y install curl
	fi
    curl https://uuwaf.uusec.com/docker.tgz -o /tmp/docker.tgz
    mkdir -p /opt && tar -zxf /tmp/docker.tgz -C /opt/
    if [ $? -ne "0" ]; then
        abort "Installation of UUSEC WAF failed"
    fi
}

allow_firewall_ports() {
    if [ ! -f "/opt/waf/.fw" ];then
        echo "" > /opt/waf/.fw
        if [ $(command -v firewall-cmd) ]; then
            firewall-cmd --permanent --add-port={80,443,4443,4447}/tcp > /dev/null 2>&1
            firewall-cmd --reload > /dev/null 2>&1
        elif [ $(command -v ufw) ]; then
            for port in 80 443 4443 4447; do ufw allow $port/tcp > /dev/null 2>&1; done
            ufw reload > /dev/null 2>&1
        fi
    fi
}

main() {
    info "Detected system: ${OS_NAME} ${OS_VERSION} ${OS_ARCH}"

    warning "Check for port conflicts ..."
    check_ports

    if [ ! -e "/opt/waf" ]; then
        warning "Install UUSEC WAF ..."
        install_waf
    else
        abort 'The directory "/opt/waf" already exists, please confirm to remove it and try again'
    fi

    warning "Add firewall ports exception ..."
    allow_firewall_ports

    bash /opt/waf/manager.sh
}

main
