# Async MTProto Proxy

Fast and simple to setup MTProto proxy written in Python.

## Starting Up

1. `git clone -b stable https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. _(optional, recommended)_ edit _config.py_, set **PORT**, **USERS** and **AD_TAG**
3. `docker-compose up -d` (or just `python3 mtprotoproxy.py` if you don't like Docker)
4. _(optional, get a link to share the proxy)_ `docker-compose logs`

![Demo](https://alexbers.com/mtprotoproxy/install_demo_v2.gif)

## Configuration

The below table lists all of the configuration that are configurable for mtproxy.

| Configuration/Environment Variable | Purpose                                                                                                                                                                                                                                                                                                                     |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| USERS                              | **(Required)** The dictionary of users. Format: name -> secret (32 hex chars), for example: `{"tg": "00000000000000000000000000000002"}`                                                                                                                                                                                    |
| MODES                              | **(Required)** The dictionary of modes. Format: `{<br># Classic mode, easy to detect <br> "classic": False,<br># Makes the proxy harder to detect<br>#Can be incompatible with very old clients<br>"secure": False,<br># Makes the proxy even more hard to detect<br># Can be incompatible with old clients<br>"tls": True` |
| TLS_DOMAIN                         | **(Optional)** The domain for TLS mode, bad clients are proxied there. Use random existing domain, proxy checks it on start. For example: "domain.ltd"                                                                                                                                                                      |
| AD_TAG                             | **(Optional)** Tag for advertising, obtainable from @MTProxybot.                                                                                                                                                                                                                                                            |
| PORT                               | **(Optional)** Port of the mtproxy is listening on (Default: 443 (HTTPS)).                                                                                                                                                                                                                                                  |

## Run with the environment variables

Define the environment variables and set _env.py_ as config file. Example: `PORT=445 TLS_DOMAIN=ya.ru python3 mtprotoproxy.py env.py`

## Channel Advertising

To advertise a channel get a tag from **@MTProxybot** and put it to _config.py_.

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

```

```
