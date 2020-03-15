#!/bin/bash

[[ $(id -u) != 0 ]] && echo -e "\n 哎呀……请使用 ${red}root ${none}用户运行 ${yellow}~(^_^) ${none}\n" && exit 1
cd /root
echo "开始安装MTProxy"
apt update 2>/dev/null
apt install wget nano git -y 2>/dev/null
yum update -y 2>/dev/null
yum install wget nano git -y 2>/dev/null
wget -qO- get.docker.com | bash
systemctl enable docker
docker version
curl -L https://github.com/docker/compose/releases/download/1.25.0-rc4/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

git clone https://github.com/alexbers/mtprotoproxy.git -b stable
cd mtprotoproxy

echo '请输入你想伪装的Fake TLS DOMAIN：'
read yumingqwq
if [ ! -n "$yumingqwq" ]; then
	echo "...既然你没有（不知道）要选哪个...那就设置成默认的 www.cloudflare.com 吧"
	yumingqwq="www.cloudflare.com"
	sed -i "s/# TLS_DOMAIN = \"www.google.com\"/TLS_DOMAIN = \"www.cloudflare.com\"/g" /root/mtprotoproxy/config.py
else
  	sed -i "s/# TLS_DOMAIN = \"www.google.com\"/TLS_DOMAIN = \"$yumingqwq\"/g" /root/mtprotoproxy/config.py
fi

echo '请输入你的AD_TAG（如果没有可以回车跳过，不影响）：'
read useradtag
if [ ! -n "$useradtag" ]; then
	echo "嗷 你没有（不用怕 不影响的"
else
  	sed -i "s/# AD_TAG = \"3c09c680b76ee91a4c25ad51f742267d\"/AD_TAG = \"$useradtag\"/g" /root/mtprotoproxy/config.py
fi


IPAddress=$(curl -sSL https://www.bt.cn/Api/getIpAddress)
HEXVAL=$(xxd -pu <<< "$yumingqwq")
domainhex=${HEXVAL%0a}
docker-compose up -d
echo "请等待 20 秒..."
sleep 20
echo "你的MTProxy链接是："
echo "tg://proxy?server=$IPAddress&port=443&secret=ee00000000000000000000000000000001$domainhex"
