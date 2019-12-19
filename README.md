# Async MTProto Proxy

Fast and simple to setup MTProto proxy written in Python.

## Starting Up

### Docker

1. Just run: `docker run --name mtproxy --network host alexbers/mtprotoproxy`
2. _(optional, recommended)_ add desired environment variables, for example: `docker run --name mtproxy -p 8080:8080 -e PORT=8080 -e TLS_DOMAIN=google.com -e USERS='{"tg": "00000000000000000000000000000001"}' alexbers/mtprotoproxy`

### Docker (local)

1. `git clone -b stable https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. _(optional, recommended)_ edit the `environment` section in the `docker-compose.yml` and set environment variables: **PORT**, **USERS** and **AD_TAG** (see [the Configuration Table](#configuration))
3. `docker-compose up -d` (or just `python3 mtprotoproxy.py` if you don't like Docker)
4. _(optional, get a link to share the proxy)_ `docker-compose logs`

### Python (if you don't like Docker)

1. `git clone -b stable https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. _(optional, recommended)_ edit `config.py`, set environment variables: **PORT**, **USERS** and **AD_TAG** (see [the Configuration Table](#configuration))
3. `python3 mtprotoproxy.py`
4. _(optional, get a link to share the proxy)_ look in the output

![Demo](https://alexbers.com/mtprotoproxy/install_demo_v2.gif)

## Configuration

The below table lists all of the configuration that are configurable for mtproxy.

| **Variable** | **Purpose**                                                                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| USERS        | **(Recommended)** The dictionary of users. Format: `name -> secret (32 hex chars)`, for example: `{"tg": "00000000000000000000000000000002"}`          |
| MODES        | **(Recommended)** The dictionary of modes. Format: `{"classic": False, "secure": False, "tls": True}`                                                  |
| TLS_DOMAIN   | **(Optional)** The domain for TLS mode, bad clients are proxied there. Use random existing domain, proxy checks it on start. For example: "domain.ltd" |
| AD_TAG       | **(Optional)** Tag for advertising, obtainable from @MTProxybot.                                                                                       |
| PORT         | **(Optional)** Port of the mtproxy is listening on (Default: 443 (HTTPS)).                                                                             |

## MODES

| **Mode** | **Purpose**                                                                          | **Recommended** |
| -------- | ------------------------------------------------------------------------------------ | --------------- |
| classic  | Classic mode, easy to detect.                                                        | False           |
| secure   | Makes the proxy harder to detect. Can be incompatible with very old clients.         | False           |
| tls      | Makes the proxy even more hard to detect. Can be incompatible with very old clients. | True            |

## Run with the environment variables

Define the environment variables and set `env.py` as config file. Example: `PORT=445 TLS_DOMAIN=ya.ru python3 mtprotoproxy.py env.py`

## Channel Advertising

To advertise a channel get a tag from **@MTProxybot** and put it to `config.py` or `env.py`.

## Performance

The proxy performance should be enough to comfortably serve about 4 000 simultaneous users on
the VDS instance with 1 CPU core and 1024MB RAM.

## More Instructions

- [Running without Docker](https://github.com/alexbers/mtprotoproxy/wiki/Running-Without-Docker)
- [Optimization and fine tuning](https://github.com/alexbers/mtprotoproxy/wiki/Optimization-and-Fine-Tuning)

## Advanced Usage

The proxy can be launched:

- with a custom config: `python3 mtprotoproxy.py [configfile]`
- several times, clients will be automaticaly balanced between instances
- with uvloop module to get an extra speed boost
- with runtime statistics exported to [Prometheus](https://prometheus.io/)

## Development

- You can use `docker-compose-dev.yml` for a developer's purpose: `docker-compose -f docker-compose.yml -f docker-compose-dev.yml up`
