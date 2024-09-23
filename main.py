from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# Server configuration
HOST_NAME = "localhost"
SERVER_PORT = 8080

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Convert keys to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Get private key numbers to create the JWKS
numbers = private_key.private_numbers()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length for byte conversion
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    # URL-safe Base64 encoding
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path) # Parse request path
        params = parse_qs(parsed_path.query) # Parse query parameters
        
        if parsed_path.path == "/auth": # Handle authentication requests
            headers = {
                "kid": "goodKID" # Key ID for the token
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) # Set 1 hour expiration period
            }
            
            # Issue expired token to expired parameter
            if 'expired' in params:
                headers["kid"] = "expiredKID" # Assing Key ID for expired token
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1) # Set past for expiration
            
            # Use the private key to encode the JWT
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            
            self.send_response(200) # Successful response
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8")) # Send token back to client
            return

        self.send_response(405) # POST method not allowed for other paths
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json": # JWKS endpoint
            self.send_response(200) # Successful response
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            keys = {
                "keys": [
                    {
                        "alg": "RS256", # Algorithm
                        "kty": "RSA", # Key type
                        "use": "sig", # Signature
                        "kid": "goodKID", # Key ID
                        "n": int_to_base64(numbers.public_numbers.n), # Modulus
                        "e": int_to_base64(numbers.public_numbers.e), # Exponent
                    }
                ]
            }
            
            self.wfile.write(bytes(json.dumps(keys), "utf-8")) # Send JWKS as response
            return

        self.send_response(405) # GET method not allowed
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer) # Create and start the server
    try:
        webServer.serve_forever() # Run the server indefinitely
    except KeyboardInterrupt:
        pass
    
    webServer.server_close() # Clean and release resources when server is shut down