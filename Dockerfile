FROM alpine:3.11

RUN adduser tgproxy -u 10000 -D

RUN apk add --no-cache python3 py3-cryptography ca-certificates libcap

RUN setcap cap_net_bind_service=+ep /usr/bin/python3.8

COPY mtprotoproxy.py config.py /home/tgproxy/
RUN chown -R tgproxy:tgproxy /home/tgproxy

USER tgproxy

WORKDIR /home/tgproxy/
CMD ["python3", "mtprotoproxy.py"]
