# Async MTProto Proxy #

Fast and simple to setup mtproto proxy.

**This is pre-alpha. Don't recommended for production use yet**

## Starting Up ##
    
1. `git clone https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. *(optional, recommended)* edit *config.py*, set **PORT**, **USERS** and **AD_TAG**
3. `docker-compose up --build -d` (or just `python3 mtprotoproxy.py` if you don't like docker)
4. *(optional, shows telegram link to set the proxy)* `docker-compose logs`

## Channel Advertising ##

To advertise a channel get a tag from **@MTProxybot** and write it to *config.py*.
