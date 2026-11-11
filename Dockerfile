# ---- build stage: install deps, strip, set capability ----
FROM python:3.12-alpine AS build

RUN apk add --no-cache libcap
RUN pip install --no-cache-dir --target /deps cryptography uvloop PySocks

# strip python itself: drop pip, tests, GUI/devel stuff, stdlib modules the proxy never uses
RUN cd /usr/local/lib/python3.12 \
 && rm -rf ensurepip idlelib tkinter turtledemo test lib2to3 site-packages/* \
           config-3.12-* distutils unittest/test sqlite3 dbm pydoc_data \
 && rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc* /usr/local/bin/2to3* \
 && rm -rf /usr/local/include /usr/local/share \
 && find /usr/local /deps \( -name "__pycache__" -o -name "tests" \) -type d -prune -exec rm -rf {} + \
 && find /deps /usr/local -name "*.so*" -exec strip --strip-unneeded {} + 2>/dev/null || true

# allow binding :443 as non-root (xattrs survive COPY --from)
RUN setcap cap_net_bind_service=+ep /usr/local/bin/python3.12

# ---- runtime stage: plain alpine + trimmed python + deps ----
FROM alpine:3.22

RUN adduser -D -u 10000 tgproxy
COPY --from=build /usr/local /usr/local
COPY --from=build /deps /usr/local/lib/python3.12/site-packages
# shared libs python/cryptography link against
COPY --from=build /usr/lib/libffi.so* /usr/lib/libssl.so* /usr/lib/libcrypto.so* /usr/lib/libz.so* /usr/lib/libgcc_s.so* /usr/lib/

USER tgproxy
WORKDIR /home/tgproxy/
COPY --chown=tgproxy mtprotoproxy.py config.py ./

# replace the placeholder secret in config.py with a random 32-hex value generated at build time
RUN SECRET="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
 && sed -i "s/00000000000000000000000000000001/${SECRET}/" config.py \
 && grep -q "\"${SECRET}\"" config.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python3", "mtprotoproxy.py"]
