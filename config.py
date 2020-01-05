import os
PORT = 443

# name -> secret (32 hex chars)
USERS = {
    "tg":  os.environ.get("TG_KEY", "00000000000000000000000000000001"),
#    "tg2": "0123456789abcdef0123456789abcdef",
}

# Makes the proxy harder to detect
# Can be incompatible with very old clients
SECURE_ONLY = os.environ.get('SECURE_ONLY', True)

# Makes the proxy even more hard to detect
# Compatible only with the recent clients
TLS_ONLY = os.environ.get('TLS_ONLY', True)

# The domain for TLS, bad clients are proxied there
# Use random existing domain, proxy checks it on start
TLS_DOMAIN = os.environ.get('TLS_DOMAIN', 'www.google.com')

# Tag for advertising, obtainable from @MTProxybot
AD_TAG = os.environ.get('AD_TAG', '3c09c680b76ee91a4c25ad51f742267d')
