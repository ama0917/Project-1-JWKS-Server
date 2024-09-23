from jwt.exceptions import ExpiredSignatureError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import unittest
import requests
import jwt
import json
import base64

class TestJWTServer(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def setUp(self):
        # This setup assumes the server is already running
        pass

    def test_unsupported_methods(self):
        # Test unsupported HTTP methods to ensure they return a 405 Method Not Allowed
        unsupported_methods = [requests.put, requests.patch, requests.delete, requests.head]
        for method in unsupported_methods:
            with self.subTest(method=method):
                response = method(f"{self.BASE_URL}/some_endpoint")
                self.assertEqual(response.status_code, 405)

    def test_jwks_endpoint(self):
        # Test the JWKS endpoint to ensure it returns the correct JSON Web Key Set
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        
        # Check that the response status code is 200 OK
        self.assertEqual(response.status_code, 200)

        # Parse the JSON response
        data = response.json()

        self.assertIn("keys", data) # Ensure existing key fields
        self.assertEqual(len(data["keys"]), 1) # Check for one key

        key = data["keys"][0]
        self.assertEqual(key["alg"], "RS256") # Check algorithm
        self.assertEqual(key["kty"], "RSA") # Check key type
        self.assertEqual(key["use"], "sig") # Check key usage
        self.assertEqual(key["kid"], "goodKID") # Check key ID
        self.assertIn("n", key) # Ensure existing modulus
        self.assertIn("e", key) # Ensure existing exponent

    def construct_public_key(self, jwk):
        # Helper method to construct a public key from a
        e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
        n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
       
        # Create a public key from the modulus and exponent
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key()

        # Convert the public key to PEM format for verification
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem
    
    def test_auth_endpoint(self):
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        token = response.text
        
        # Verify the token
        jwks_response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        jwks = jwks_response.json()
        public_key = self.construct_public_key(jwks['keys'][0])
        
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        self.assertIn("user", decoded)
        self.assertEqual(decoded["user"], "username")

def test_expired_token(self):
    response = requests.post(f"{self.BASE_URL}/auth?expired=true")
    self.assertEqual(response.status_code, 200)

    token = response.text
    
    # Manually construct the public key for testing
    public_key = self.construct_public_key({
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "kid": "goodKID",
        "n": "some_n_value",
        "e": "AQAB"
    })
    
    with self.assertRaises(ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])

if __name__ == "__main__":
    unittest.main()