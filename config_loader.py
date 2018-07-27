import runpy
import socket
from utils import print_err


def load_config(config, path):
    config_mod = runpy.run_path(path)

    async def async_nop(*args, **kwargs): pass

    config_options = [
        ("PORT", 3256),
        ("USERS", None),
        ("AD_TAG", ""),
        ("PREFER_IPV6", socket.has_ipv6),
        ("FAST_MODE", True),
        ("STATS_PRINT_PERIOD", 10*60),
        ("PROXY_INFO_UPDATE_PERIOD", 24*60*60),
        ("TO_CLT_BUFSIZE", 16384),
        ("TO_TG_BUFSIZE", 65536),
        ("CLIENT_KEEPALIVE", 10*60),
        ("CLIENT_HANDSHAKE_TIMEOUT", 10),
        ("CLIENT_ACK_TIMEOUT", 5*60),
        ("TG_CONNECT_TIMEOUT", 10),
        ("STATS_UPDATE_HOOK", async_nop),
        ("INIT_HOOK", async_nop)
    ]

    ok = True

    for option, default in config_options:
        config[option] = config_mod.get(option, default)

        if config[option] is None:
            print_err("Missing required option", option)
            ok = False

    if len(config["AD_TAG"]) > 0:
        config["AD_TAG"] = bytes.fromhex(config["AD_TAG"])
    else:
        config["AD_TAG"] = None

    config["USE_MIDDLE_PROXY"] = config["AD_TAG"] is not None

    return ok
