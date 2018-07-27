import sys


def dict_get_or_else(self, k, f):
    if k not in self:
        self[k] = f()

    return self[k]


def print_err(*params):
    print(*params, file=sys.stderr, flush=True)


class LayeredStreamReaderBase:
    def __init__(self, upstream):
        self.upstream = upstream

    async def read(self, n):
        return await self.upstream.read(n)

    async def readexactly(self, n):
        return await self.upstream.readexactly(n)


class LayeredStreamWriterBase:
    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        return self.upstream.write(data)

    def write_eof(self):
        return self.upstream.write_eof()

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def abort(self):
        return self.upstream.transport.abort()

    @property
    def transport(self):
        return self.upstream.transport
