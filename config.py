import os
PORT = os.getenv('conf_port')

# name -> secret (32 hex chars)
USERS = {
    "tg":  os.getenv('conf_secret'),
}

# Tag for advertising, obtainable from @MTProxybot
AD_TAG = os.getenv('conf_ad_tag')
