#!/bin/bash

pause() {
	read -rsp "$(echo -e "按$green Enter 回车键 $none继续....或按$red Ctrl + C $none取消.")" -d $'\n'
	echo
}
red='\e[91m'
none='\e[0m'

[[ $(id -u) != 0 ]] && echo -e "哎呀......请使用 ${red}root ${none}用户运行 ${yellow}~(^_^) ${none}\n" && exit 1
clear
echo "--------------------"
echo "1) 安装"
echo "2) 卸载"
echo "0) 退出"
echo "--------------------"
echo "Telegram: https://t.me/kldgodynb"
echo "--------------------"
echo "请输入命令:"
read choice
if [ "$choice" = "1" ]; then
	cd /root
	echo "开始安装MTProxy"
	
	#安装必要组件
	apt-update 2>/dev/null
	apt-insall wget nano git -y 2>/dev/null
	yum update 2>/dev/null
	yum install wget nano git -y 2>/dev/null
	wget -qO- get.docker.com | sh
	systemctl enable docker
	curl -L https://github.com/docker/compose/releases/download/1.25.0-rc4/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
	chmod +x /usr/local/bin/docker-compose
	
	#Clone & cd
	git clone https://github.com/alexbers/mtprotoproxy.git -b stable
	cd mtprotoproxy
	
	#Fake TLS domain
	while true
	do
		echo "请输入需要伪装的域名:"
		read domain
		if [ ! -n "$domain" ]; then
			echo "使用默认域名: www.cloudflare.com"
			sed -i "s/# TLS_DOMAIN = \"www.google.com\"/TLS_DOMAIN = \"www.cloudflare.com\"/g" /root/mtprotoproxy/config.py
			domain='www.cloudflare.com'
			break
		else
			http_code=$(curl -I -m 10 -o /dev/null -s -w %{http_code} $domain)
			if [ $http_code -eq "200" ] || [ $http_code -eq "302" ]; then
				sed -i "s/# TLS_DOMAIN = \"www.google.com\"/TLS_DOMAIN = \"$domain\"/g" /root/mtprotoproxy/config.py
				break
			fi
		fi
		echo -e "[\033[33m错误\033[0m] 域名无法访问,请重新输入或更换域名!"
	done
	
	#AG_TAG
	echo "请输入你的AD_TAG(留空则跳过):"
	read adtag
		sed -i "s/# AD_TAG = \"3c09c680b76ee91a4c25ad51f742267d\"/AD_TAG = \"$adtag\"/g" /root/mtprotoproxy/config.py
	
	echo "请确认配置是否有误"
	echo "--------------------"
	echo "Port: 443"
	echo "Fake TLS domain: $domain"
	echo "AD_TAG: $adtag"
	echo "--------------------"
	pause
	
	#获取IP
	IPAddress=$(curl -sSL https://www.bt.cn/Api/getIpAddress)
	#计算域名hex值
	hexxxxxx=$(xxd -pu <<< "$domain")
	hexvel=$(xxd -pu <<< "$domain")
	domainhex=${hexvel%0a}
	docker-compose up -d
	clear
	echo "--------------------"
	echo "你的MTProxy链接是:"
	echo "tg://proxy?server=$IPAddress&port=443&secret=ee00000000000000000000000000000001$domainhex"
	echo "--------------------"
	echo "Telegram: https://t.me/kldgodynb"

elif [ "$choice" = "2" ]; then
	if [ ! -d "/root/mtprotoproxy" ]; then
		echo "宝贝,都没安装呢:("
	else
		cd /root/mtprotoproxy && docker stop mtprotoproxy_mtprotoproxy_1 && docker rm mtprotoproxy_mtprotoproxy_1 && rm -rf /root/mtprotoproxy
		echo "卸载完成!"
	fi
elif [ "$choice" = "0" ]; then
	exit

else
	echo "???你输入的东西 这个辣鸡脚本不懂诶:("
fi
