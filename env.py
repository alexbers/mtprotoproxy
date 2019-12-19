import os
import ast
# See the documentation about the configuration
PORT = os.getenv("PORT", 443)
USERS = ast.literal_eval(os.getenv("USERS", "{\"tg\":\"00000000000000000000000000000002\"}"))
MODES = ast.literal_eval(os.getenv("MODES", "{\"classic\": False,\"secure\": False,\"tls\": True}"))
TLS_DOMAIN = os.getenv("TLS_DOMAIN", "www.google.com")
AD_TAG = os.getenv("AD_TAG","")
