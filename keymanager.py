from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class RSAKeyManager:
    """
    Manages RSA key generation and encoding. Can operate in secure mode for real-world
    use with larger primes or in test mode with small primes.
    """
    def __init__(self, secure=False):
        """
        Initializes the RSAKeyManager.
        :param secure: Boolean, True to use high-security keys, False for demonstration with small primes.
        """
        self.secure = secure
        if not self.secure:
            # Small primes for demonstration purposes
            self.p = 13
            self.q = 7
            self.e = 5
            self.public_key, self.private_key = self.generate_rsa_keys(self.p, self.q, self.e)
        else:
            # Generate a high-security private key
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()

    def generate_rsa_keys(self, p, q, e):
        """
        Generates RSA public and private keys using provided primes and exponent.
        :param p: Prime number
        :param q: Prime number
        :param e: Public exponent
        :return: Tuple of (public_key, private_key), or (None, None) if invalid parameters.
        """
        n = p * q
        phi = (p - 1) * (q - 1)
        d = self.inv_mod(e, phi)
        if d == -1:
            return None, None
        public_numbers = rsa.RSAPublicNumbers(e, n)
        private_numbers = rsa.RSAPrivateNumbers(p, q, d, d % (p-1), d % (q-1), self.inv_mod(q, p), public_numbers)
        return public_numbers.public_key(default_backend()), private_numbers.private_key(default_backend())

    @staticmethod
    def inv_mod(a, b):
        """
        Computes the modular inverse of a under modulo b using the Extended Euclidean Algorithm.
        :param a: Integer, the number to find the inverse for.
        :param b: Integer, the modulo.
        :return: Integer, the modular inverse if one exists, or -1 if no inverse exists.
        """
        x, y, u, v = 0, 1, 1, 0
        while a != 0:
            q, r = b//a, b % a
            m, n = x-u*q, y-v*q
            b, a, x, y, u, v = a, r, u, v, m, n
        gcd = b
        return x % b if gcd == 1 else -1

    def get_public_key_pem(self):
        """
        Returns the public key in PEM format.
        :return: PEM encoded public key.
        """
        return self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def get_public_key_from_pem(pem):
    """
    Returns the public key given a public key in PEM format.
    :return: public key.
    """
    return serialization.load_pem_public_key
