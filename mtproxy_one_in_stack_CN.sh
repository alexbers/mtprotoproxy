#!/bin/bash

red='\e[91m'
none='\e[0m'

[[ $(id -u) != 0 ]] && echo -e "哎呀......请使用 ${red}root ${none}用户运行 ${yellow}~(^_^) ${none}\n" && exit 1
echo "--------------------"
echo "1) 安装"
echo "2) 卸载"
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
	echo "请输入需要伪装的域名:"
	read domain
	if [ ! -n "$domain" ]; then
		echo "使用默认域名: www.cloudflare.com"
		sed -i "s/# TLS_DOMAIN = \"www.google.com\"/TLS_DOMAIN = \"www.cloudflare.com\"/g" /root/mtprotoproxy/config.py
	else
		sed -i "s/# TLS_DOMAIN = \"www.google.com\"/TLS_DOMAIN = \"$domain\"/g" /root/mtprotoproxy/config.py
	fi
	
	#AG_TAG
	echo "请输入你的AD_TAG(留空则跳过):"
	read adtag
	sed -i "s/# AD_TAG = \"3c09c680b76ee91a4c25ad51f742267d\"/AD_TAG = \"$adtag\"/g" /root/mtprotoproxy/config.py
	
	echo "请确认配置是否有误,无误请回车"
	echo "--------------------"
	echo "Port: 443"
	echo "Fake TLS domain: $domain"
	echo "AD_TAG: $adtag"
	echo "--------------------"
	read faiusfgfuasfgasfbasfvayfgaf
	
	#获取IP
	IPAddress=$(curl -sSL https://www.bt.cn/Api/getIpAddress)
	#计算域名hex值
	hexxxxxx=$(xxd -pu <<< "$domain")
	HEXVAL=$(xxd -pu <<< "$domain")
	docker-compose up -d
	echo "你的MTProxy链接是:"
	echo "tg://proxy?server=$IPAddress&port=443&secret=ee00000000000000000000000000000001$domainhex"

elif [ "$choice" = "2" ]; then
	if [ ! -d "/root/mtprotoproxy" ]; then
		echo "宝贝,都没安装呢:("
	else
		cd /root/mtprotoproxy && docker stop mtprotoproxy_mtprotoproxy_1 && docker rm mtprotoproxy_mtprotoproxy_1 && rm -rf /root/mtprotoproxy
		echo "卸载完成!"
	fi

else
	echo "???你输入的东西 这个辣鸡脚本不懂诶:("
fi
