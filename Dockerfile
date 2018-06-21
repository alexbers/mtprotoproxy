FROM alpine:3.6

RUN adduser tgproxy -u 10000 -D

RUN apk add --no-cache python3 py3-crypto ca-certificates libcap

COPY mtprotoproxy.py config.py /home/tgproxy/
COPY pyaes/*.py /home/tgproxy/pyaes/

RUN chown -R tgproxy:tgproxy /home/tgproxy
RUN setcap cap_net_bind_service=+ep /usr/bin/python3.6

USER tgproxy

WORKDIR /home/tgproxy/
CMD ["./mtprotoproxy.py"]
