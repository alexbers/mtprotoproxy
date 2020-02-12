FROM python:3.8-slim-buster

RUN apt-get update && apt-get install -y libcap2-bin \
    && setcap cap_net_bind_service=+ep /usr/local/bin/python3.8 \
    && apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN pip3 --no-cache-dir install cryptography uvloop

COPY mtprotoproxy.py config.py /home/tgproxy/

RUN useradd tgproxy -u 10000
RUN chown -R tgproxy:tgproxy /home/tgproxy

USER tgproxy

WORKDIR /home/tgproxy/
CMD ["python3", "mtprotoproxy.py"]
