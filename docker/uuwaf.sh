#!/bin/bash

warning() {
	echo -e "\033[33m[UUSEC WAF] $*\033[0m"
}

abort() {
	echo -e "\033[31m[UUSEC WAF] $*\033[0m"
	exit 1
}

if [ -z "$BASH" ]; then
	abort "Please execute this script using bash and refer to the latest official technical documentation https://uuwaf.uusec.com/"
fi

if [ "$EUID" -ne "0" ]; then
	abort "Please run with root privileges"
fi

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd  "$SCRIPT_PATH"

if [ ! $(command -v docker) ]; then
	warning "Docker Engine not detected, we will automatically install it for you. The process is slow, please be patient ..."
	sh install-docker.sh
	if [ $? -ne "0" ]; then
		abort "Automatic installation of Docker Engine failed. Please manually install it before executing this script"
	fi
	systemctl enable docker && systemctl daemon-reload && systemctl restart docker
fi

DC_CMD="docker compose"
$DC_CMD version > /dev/null 2>&1
if [ $? -ne "0" ]; then
	abort "Your Docker version is too low and lacks the Docker compose command. Please uninstall and install the latest version"
fi

stop_uuwaf(){
	$DC_CMD down
}

uninstall_uuwaf(){
	stop_uuwaf
	docker rm -f uuwaf wafdb > /dev/null 2>&1
	docker network rm wafnet > /dev/null 2>&1
	docker images|grep uuwaf|awk '{print $3}'|xargs docker rmi -f > /dev/null 2>&1
	docker volume ls|grep waf|awk '{print $2}'|xargs docker volume rm -f > /dev/null 2>&1
}

start_uuwaf(){
	if [ ! $(command -v netstat) ]; then
		$( command -v yum || command -v apt-get ) -y install net-tools
	fi
	port_status=`netstat -nlt|grep -E ':(80|443|4443)\s'|wc -l`
	if [ $port_status -gt 0 ]; then
		echo -e "\t One or more of ports 80, 443, 4443 are occupied. Please shut down the corresponding service or modify its port"
		exit 1
	fi
	$DC_CMD up -d --remove-orphans
}

upgrade_uuwaf(){
	$DC_CMD pull
	$DC_CMD up -d --remove-orphans
}

repair_uuwaf(){
	systemctl restart firewalld ufw
	systemctl daemon-reload
	systemctl restart docker
}

restart_uuwaf(){
	stop_uuwaf
	start_uuwaf
}

clean_uuwaf(){
	docker system prune -a -f
	docker volume prune -a -f
}

start_menu(){
    clear
    echo "========================="
    echo "UUSEC WAF Docker Management"
    echo "========================="
    echo "1. Start"
    echo "2. Stop"
    echo "3. Restart"
    echo "4. Upgrade"
    echo "5. Repair"
    echo "6. Uninstall"
    echo "7. Clean"
    echo "8. Exit"
    echo
    read -p "Please enter the number: " num
    case "$num" in
    	1)
	start_uuwaf
	echo "Startup completed"
	;;
	2)
	stop_uuwaf
	echo "Stop completed"
	;;
    	3)
	restart_uuwaf
	echo "Restart completed"
	;;
	4)
	upgrade_uuwaf
	echo "Upgrade completed"
	;;
	5)
	repair_uuwaf
	echo "Repair completed"
	;;
	6)
	uninstall_uuwaf
	echo "Uninstall completed"
	;;
	7)
	clean_uuwaf
	echo "Clean completed"
	;;
	8)
	exit 1
	;;
	*)
	clear
	echo "Please enter the right number"
	;;
    esac
    sleep 3s
    start_menu
}

start_menu
