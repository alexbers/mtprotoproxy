PORT = 443

# name -> secret (32 hex chars)
USERS = {
    "tg":  "00000000000000000000000000000001",
    # "tg2": "0123456789abcdef0123456789abcdef",
}

MODES = {
    # Classic mode, easy to detect
    "classic": False,

    # Makes the proxy harder to detect
    # Can be incompatible with very old clients
    "secure": False,

    # Makes the proxy even more hard to detect
    # Can be incompatible with old clients
    "tls": True
}

# The domain for TLS mode, bad clients are proxied there
# Use random existing domain, proxy checks it on start
# TLS_DOMAIN = "www.google.com"

# Prometheus exporter host and port for the dedicated endpoint
PROMETHEUS_HOST = "0.0.0.0"
PROMETHEUS_PORT = 9100

# Prometheus scrapers whitelist for safety
PROMETHEUS_SCRAPERS = ["127.0.0.1", "::1"]
