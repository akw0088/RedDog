from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import ssl

class RequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		content_len = self.headers.get('Content-Length')
		try:
			request_body = self.rfile.read(int(content_len))
			print(request_body.decode("utf8"))
		except Exception as err:
			print(err)
			return

		message = input("Enter command: ")
		self.protocol_version = "HTTP/1.1"
		self.send_response(200)
		self.send_header("Content-Length", len(message))
		self.end_headers()
		self.wfile.write(bytes(message, "utf8"))

		return

def run():
	server = ('127.0.0.1', 80)
	httpd = HTTPServer(server, RequestHandler)
	#httpd.socket = ssl.wrap_socket(httpd.socket, keyfile = "C:\\OpenSSL-Win32\\bin\\cert.key", certfile = "C:\\OpenSSL-Win32\\bin\\cert.pem", server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
	print("\nWaiting for RedDog...\n")
	httpd.serve_forever()
run()
