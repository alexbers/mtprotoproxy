# Async MTProto Proxy #

Fast and simple to setup mtproto proxy.

## Starting Up ##
    
1. *(optional, recommended)* `pip install uvloop`
2. `pip install mtprotoproxy`
3. `mtprotoproxy <port> <secret> [ad_tag] [tls_domain]`. Example: `mtprotoproxy 443 d14c0fb43d4bb5be3184037560fb146c 3c09c680b76ee91a4c25ad51f742267d google.com`

## Channel Advertising ##

To advertise a channel get a tag from **@MTProxybot**.

## Performance ##

The proxy performance should be enough to comfortably serve about 4 000 simultaneous users on
the VDS instance with 1 CPU core and 1024MB RAM.

## Advanced Usage ##

The proxy can be launched:
- with a custom config: `python3 mtprotoproxy.py [configfile]`
- several times, clients will be automaticaly balanced between instances
