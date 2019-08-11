PORT = 3256

# name -> secret (32 hex chars)
USERS = {
    "tg":  "00000000000000000000000000000000",
    "tg2": "0123456789abcdef0123456789abcdef"
}

# Makes the proxy harder to detect
# Can be incompatible with very old clients
SECURE_ONLY = True

# Makes the proxy even more hard to detect
# Compatible only with the recent clients
# TLS_ONLY = True

# Tag for advertising, obtainable from @MTProxybot
# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"
