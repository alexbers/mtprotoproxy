# Async mtproto proxy #

Fast and simple to setup mtproto proxy.

**This is pre-alpha. Don't recommended for production use yet**

## Starting up ##
    
1. `git clone https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. *(optional, recommended)* edit *config.py*, set **PORT** and **USERS**
3. `docker-compose up --build -d` (or just `python3 mtprotoproxy.py` if you don't like docker)
4. *(optional, shows telegram link to set the proxy)* `docker-compose logs`
