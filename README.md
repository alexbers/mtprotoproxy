# Async MTProto Proxy #

Fast and simple to setup MTProto proxy written in Python.

## Starting Up ##
    
1. `git clone -b stable https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. *(optional)* edit *config.py*, set **PORT** and **AD_TAG**. Leave the placeholder secret
   `00000000000000000000000000000001` in **USERS** as is: the Docker build replaces it with a random
   32-hex-char secret, so every image gets its own secret.
3. `docker-compose up -d --build` (or just `python3 mtprotoproxy.py` if you don't like Docker; note that
   without Docker the placeholder secret is used as is, so set your own)
4. *(get a link to share the proxy, it contains the generated secret)* `docker-compose logs`

The secret is generated at image build time. Docker reuses cached layers, so to get a new secret
rebuild with `docker-compose build --no-cache`. Config changes require a rebuild, since *config.py* is
baked into the image. If you instead mount your own *config.py* as a volume, the generated secret is overridden.

![Demo](https://alexbers.com/mtprotoproxy/install_demo_v2.gif)

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
