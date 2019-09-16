from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import json

class ServerThread(Thread):
    def __init__(self, name, config):
        Thread.__init__(self)
        self.name = name
        self.config = config

    def run(self):
      server_class = HTTPServer
      httpd = server_class(('127.0.0.1', self.config['API_PORT']), APIHandler(self.config))
      httpd.server_forever()

class APIHandler(BaseHTTPRequestHandler):
    def __init__(self, config):
        self.config = config
        super().__init__()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_GET(self):
        paths = ['/']
        if self.path in paths:
            self.respond({'status': 200, 'content' : self.dump_config()})
        else:
            self.respond({'status': 404})

    def dump_config(self):
        data = {
            'deeplinks': self.config['ACTIVATORS']
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def handle_http(self, status_code, content):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        return bytes(content, 'utf-8')

    def respond(self, opts):
        response = self.handle_http(opts['status'], opts['content'])
        self.wfile.write(response)


def start_api(config):
    ServerThread(config).start()