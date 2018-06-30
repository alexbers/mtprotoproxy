PORT = 3256

# name -> secret (32 hex chars)
USERS = {
    "tg":  "00000000000000000000000000000000",
    "tg2": "0123456789abcdef0123456789abcdef"
}

# If you run two or more instances on same `PORT`, they should have _different_
# prometheus ports to produce meaningful stats.
# PROMETHEUS_PORT = 9500

# Tag for advertising, obtainable from @MTProxybot
# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"
