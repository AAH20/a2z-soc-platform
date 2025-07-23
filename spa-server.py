#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
from urllib.parse import urlparse

class SPAHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Remove leading slash
        if path.startswith('/'):
            path = path[1:]
        
        # If no path or it's a route (not a file), serve index.html
        if not path or (not os.path.exists(path) and not path.startswith('assets/')):
            self.path = '/index.html'
        
        return super().do_GET()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    
    # Change to the directory containing the built React app
    os.chdir('/app/dist')
    
    with socketserver.TCPServer(("", port), SPAHTTPRequestHandler) as httpd:
        print(f"🎨 SPA Server running on http://localhost:{port}")
        print(f"📁 Serving from: {os.getcwd()}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 SPA Server shutting down...")
            httpd.shutdown()

if __name__ == "__main__":
    main() 