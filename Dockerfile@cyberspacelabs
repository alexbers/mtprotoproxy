FROM ubuntu:18.04
ENV SNI=www.google.com
ENV PROXY_PORT=3256
ENV API_PORT=3257
ENV SECRET=08ca404ff6d62e9de1e15132a71a3ba0
ENV PYTHONPATH="${PYTHONPATH}:/opt/mtproxy"
RUN apt-get -y update && apt-get -y install python3 python3-cryptography
RUN mkdir -p /opt/mtproxy
COPY . /opt/mtproxy/
WORKDIR /opt/mtproxy
ENTRYPOINT ./mtprotoproxy.py faketls ${SNI} ${PROXY_PORT} ${API_PORT} ${SECRET}
