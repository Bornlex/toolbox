#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

PORT_NUMBER = 8080

class myHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("[request] GET request")
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write("Hello World !")
        return

try:
    server=HTTPServer(('', PORT_NUMBER), myHandler)
    print("[server] server started")
    server.serve_forever()
except KeyboardInterrupt:
    print("[interrupt] interruption requested")
    server.socket.close()
