FROM python:3.8-slim-buster

RUN apt-get update && apt-get install --no-install-recommends -y libcap2-bin && rm -rf /var/lib/apt/lists/*
RUN setcap cap_net_bind_service=+ep /usr/local/bin/python3.8

RUN pip3 --no-cache-dir install cryptography uvloop

RUN useradd tgproxy -u 10000

USER tgproxy

WORKDIR /home/tgproxy/

COPY --chown=tgproxy mtprotoproxy.py config.py /home/tgproxy/

CMD ["python3", "mtprotoproxy.py"]
