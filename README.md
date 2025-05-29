# Async MTProto Proxy #

Fast and simple to setup MTProto proxy written in Python.

## Starting Up ##
    
1. `git clone -b stable https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. *(optional, recommended)* edit *config.py*, set **PORT**, **USERS** and **AD_TAG**
3. `docker-compose up -d` (or just `python3 mtprotoproxy.py` if you don't like Docker)
4. *(optional, get a link to share the proxy)* `docker-compose logs`

![Demo](https://alexbers.com/mtprotoproxy/install_demo_v2.gif)

## User Management ##

The proxy comes with a command-line tool to easily manage users:

1. Add a new user with auto-generated secret:
```bash
./manage_users.py add username
# Output: User username added successfully with secret: 1234567890abcdef1234567890abcdef
```

2. Add a user with specific secret:
```bash
./manage_users.py add username 00000000000000000000000000000001
```

3. List all users:
```bash
./manage_users.py list
```

4. Remove a user:
```bash
./manage_users.py remove username
```

The changes are applied immediately thanks to the hot reload feature - no need to restart the proxy.

## Channel Advertising ##

To advertise a channel get a tag from **@MTProxybot** and put it to *config.py*.

## Performance ##

The proxy performance should be enough to comfortably serve about 4 000 simultaneous users on
the VDS instance with 1 CPU core and 1024MB RAM.

## More Instructions ##

- [Running without Docker](https://github.com/alexbers/mtprotoproxy/wiki/Running-Without-Docker)
- [Optimization and fine tuning](https://github.com/alexbers/mtprotoproxy/wiki/Optimization-and-Fine-Tuning)

## Advanced Usage ##

The proxy can be launched:
- with a custom config: `python3 mtprotoproxy.py [configfile]`
- several times, clients will be automaticaly balanced between instances
- with uvloop module to get an extra speed boost
- with runtime statistics exported to [Prometheus](https://prometheus.io/)
