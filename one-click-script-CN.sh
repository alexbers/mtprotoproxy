#!/bin/bash
#参考了 https://github.com/chummumm/one-key-mtp
cd /root
echo "开始安装MTProxy..."
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

echo '请输入伪装域名：'
read yumingqwq
if [ ! -n "$yumingqwq" ]; then
	echo "...你竟然什么都不输，，那伪装域名就设置成默认的 www.cloudflare.com 了（"
	sed -i 's/# TLS_DOMAIN = "www.google.com"/TLS_DOMAIN = "www.cloudflare.com"/g' /root/mtprotoproxy/config.py
	yumingqwq="www.cloudflare.com"
else
	echo "好力 按你的要求 伪装域名已被设置成 $yumingqwq"
  	sed -i 's/# TLS_DOMAIN = "www.google.com"/TLS_DOMAIN = "$yumingqwq"/g' /root/mtprotoproxy/config.py
fi
IPAddress=$(curl -sSL https://www.bt.cn/Api/getIpAddress)
HEXVAL=$(xxd -pu <<< "$yumingqwq")
domainhex=${HEXVAL%0a}
docker-compose up -d
echo "请等待 20秒..."
sleep 20
echo "您的 MTProxy链接事："
echo "tg://proxy?server=$IPAddress&port=443&secret=ee00000000000000000000000000000001$domainhex"
