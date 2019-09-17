from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import json

CONFIG = {}

class ServerThread(Thread):
    def __init__(self, name):
        Thread.__init__(self)
        self.name = name

    def run(self):
        global CONFIG
        server_class = HTTPServer
        httpd = server_class(('0.0.0.0', CONFIG['API_PORT']), APIHandler)
        httpd.serve_forever()

class APIHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_GET(self):
        paths = ['/']
        if self.path in paths:
            self.respond({'status': 200, 'content' : self.dump_config()})
        else:
            self.respond({'status': 404, 'content': 'Not found'})

    def dump_config(self):
        global CONFIG
        data = {
            'deeplinks': CONFIG['ACTIVATORS']
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
    global CONFIG
    CONFIG = config
    ServerThread('API Server').start()
