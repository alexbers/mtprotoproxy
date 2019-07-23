FROM alpine:3.10

RUN adduser tgproxy -u 10000 -D

RUN apk add --no-cache python3 py3-cryptography ca-certificates libcap

RUN chown -R tgproxy:tgproxy /home/tgproxy
RUN setcap cap_net_bind_service=+ep /usr/bin/python3.7

USER tgproxy

WORKDIR /home/tgproxy/
CMD ["python3", "mtprotoproxy.py"]
